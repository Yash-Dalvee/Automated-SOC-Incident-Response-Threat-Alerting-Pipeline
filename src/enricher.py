"""
src/enricher.py
=================
Threat intelligence enrichment for extracted IOCs.

Integrates with:
    - VirusTotal API v3   (file hash reputation, IP reputation, domain reputation)
    - AbuseIPDB API v2    (IP abuse confidence scoring)

Implements:
    - Per-provider token-bucket rate limiting (requests_per_minute from config)
    - Exponential backoff with jitter on 429 / 5xx / network errors
    - A deterministic MOCK MODE that fabricates realistic-looking responses
      so the full pipeline can be demonstrated without live API credentials
    - Normalization of both providers' outputs into a single 0-100 risk score
      and severity classification (CRITICAL / HIGH / MEDIUM / LOW / CLEAN)
"""

from __future__ import annotations

import hashlib
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

import requests
from pydantic import BaseModel

from src.parser import IOC

logger = logging.getLogger("soc_ir_pipeline.enricher")


# ------------------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------------------

class EnrichmentResult(BaseModel):
    """Normalized enrichment outcome for a single IOC."""

    ioc_type: str
    value: str
    provider: str
    score: int  # 0-100 normalized risk score
    malicious_votes: int = 0
    total_votes: int = 0
    details: dict[str, Any] = {}
    error: str | None = None


SEVERITY_ORDER = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def classify_severity(score: int, thresholds: dict[str, int]) -> str:
    """Maps a 0-100 risk score to a severity label using configured thresholds."""
    if score >= thresholds.get("critical", 80):
        return "CRITICAL"
    if score >= thresholds.get("high", 50):
        return "HIGH"
    if score >= thresholds.get("medium", 20):
        return "MEDIUM"
    if score >= thresholds.get("low", 1):
        return "LOW"
    return "CLEAN"


def highest_severity(severities: list[str]) -> str:
    """Returns the most severe label from a list, per SEVERITY_ORDER."""
    if not severities:
        return "CLEAN"
    return max(severities, key=lambda s: SEVERITY_ORDER.index(s))


# ------------------------------------------------------------------------------
# Rate limiter
# ------------------------------------------------------------------------------

class RateLimiter:
    """
    Simple token-bucket-style rate limiter enforcing a maximum number of
    requests per rolling 60-second window. Blocks (sleeps) the calling
    thread when the limit would be exceeded.
    """

    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = max(1, requests_per_minute)
        self._timestamps: list[float] = []

    def acquire(self) -> None:
        now = time.monotonic()
        window_start = now - 60.0
        self._timestamps = [t for t in self._timestamps if t > window_start]

        if len(self._timestamps) >= self.requests_per_minute:
            oldest = self._timestamps[0]
            sleep_for = 60.0 - (now - oldest) + 0.05
            if sleep_for > 0:
                logger.debug("Rate limit reached, sleeping %.2fs", sleep_for)
                time.sleep(sleep_for)

        self._timestamps.append(time.monotonic())


# ------------------------------------------------------------------------------
# HTTP helper with exponential backoff
# ------------------------------------------------------------------------------

def _request_with_backoff(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: int = 15,
    max_retries: int = 5,
    backoff_base: float = 2.0,
    backoff_max: float = 60.0,
) -> requests.Response:
    """
    Performs an HTTP request with exponential backoff + jitter on transient
    failures (HTTP 429 / 5xx / connection errors). Raises the last exception
    or returns the final response after retries are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            response = requests.request(
                method, url, headers=headers, params=params, timeout=timeout
            )
            if response.status_code == 429 or response.status_code >= 500:
                delay = min(backoff_max, backoff_base * (2 ** attempt))
                delay += random.uniform(0, 1)  # jitter
                logger.warning(
                    "Transient HTTP %s from %s, retrying in %.1fs (attempt %d/%d)",
                    response.status_code, url, delay, attempt + 1, max_retries,
                )
                time.sleep(delay)
                continue
            return response
        except requests.RequestException as exc:
            last_exc = exc
            delay = min(backoff_max, backoff_base * (2 ** attempt))
            delay += random.uniform(0, 1)
            logger.warning(
                "Request error on %s: %s, retrying in %.1fs (attempt %d/%d)",
                url, exc, delay, attempt + 1, max_retries,
            )
            time.sleep(delay)

    if last_exc:
        raise last_exc
    raise RuntimeError(f"Exhausted retries against {url} without success")


# ------------------------------------------------------------------------------
# Enricher
# ------------------------------------------------------------------------------

class ThreatIntelEnricher:
    """
    Orchestrates enrichment of IOCs against VirusTotal and AbuseIPDB,
    respecting per-provider rate limits and falling back to deterministic
    mock data when test_mode is enabled or an API key is absent.
    """

    def __init__(
        self,
        config: dict[str, Any],
        vt_api_key: str | None,
        abuseipdb_api_key: str | None,
        test_mode: bool = True,
    ):
        self.config = config
        self.vt_api_key = vt_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.test_mode = test_mode

        vt_cfg = config.get("virustotal", {})
        abuse_cfg = config.get("abuseipdb", {})

        self.vt_base_url = vt_cfg.get("base_url", "https://www.virustotal.com/api/v3")
        self.vt_rate_limiter = RateLimiter(vt_cfg.get("requests_per_minute", 4))
        self.vt_max_retries = vt_cfg.get("max_retries", 5)
        self.vt_backoff_base = vt_cfg.get("backoff_base_seconds", 2)
        self.vt_backoff_max = vt_cfg.get("backoff_max_seconds", 60)
        self.vt_timeout = vt_cfg.get("request_timeout_seconds", 15)

        self.abuse_base_url = abuse_cfg.get("base_url", "https://api.abuseipdb.com/api/v2")
        self.abuse_rate_limiter = RateLimiter(abuse_cfg.get("requests_per_minute", 60))
        self.abuse_max_retries = abuse_cfg.get("max_retries", 5)
        self.abuse_backoff_base = abuse_cfg.get("backoff_base_seconds", 2)
        self.abuse_backoff_max = abuse_cfg.get("backoff_max_seconds", 60)
        self.abuse_timeout = abuse_cfg.get("request_timeout_seconds", 15)
        self.abuse_max_age_days = abuse_cfg.get("max_age_in_days", 90)

        if not self.test_mode and not (self.vt_api_key and self.abuseipdb_api_key):
            logger.warning(
                "test_mode is False but one or more API keys are missing; "
                "falling back to mock responses for missing-key providers."
            )

    # -- Public dispatch -----------------------------------------------------

    def enrich(self, ioc: IOC) -> EnrichmentResult:
        """Routes an IOC to the appropriate provider(s) and returns a result."""
        if ioc.ioc_type == "ipv4":
            return self._enrich_ip(ioc.value)
        if ioc.ioc_type in ("sha256", "md5"):
            return self._enrich_hash(ioc.value)
        if ioc.ioc_type == "domain":
            return self._enrich_domain(ioc.value)
        return EnrichmentResult(
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            provider="none",
            score=0,
            error=f"Unsupported IOC type: {ioc.ioc_type}",
        )

    def enrich_many(self, iocs: list[IOC]) -> list[EnrichmentResult]:
        return [self.enrich(ioc) for ioc in iocs]

    # -- IP enrichment (AbuseIPDB, primary; VT as secondary signal) ---------

    def _enrich_ip(self, ip: str) -> EnrichmentResult:
        if self.test_mode or not self.abuseipdb_api_key:
            return self._mock_ip_result(ip)

        self.abuse_rate_limiter.acquire()
        try:
            response = _request_with_backoff(
                "GET",
                f"{self.abuse_base_url}/check",
                headers={
                    "Key": self.abuseipdb_api_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": self.abuse_max_age_days},
                timeout=self.abuse_timeout,
                max_retries=self.abuse_max_retries,
                backoff_base=self.abuse_backoff_base,
                backoff_max=self.abuse_backoff_max,
            )
            if response.status_code != 200:
                logger.error("AbuseIPDB error %s for %s", response.status_code, ip)
                return EnrichmentResult(
                    ioc_type="ipv4", value=ip, provider="abuseipdb", score=0,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )
            data = response.json().get("data", {})
            confidence = int(data.get("abuseConfidenceScore", 0))
            return EnrichmentResult(
                ioc_type="ipv4",
                value=ip,
                provider="abuseipdb",
                score=confidence,
                malicious_votes=int(data.get("totalReports", 0)),
                total_votes=int(data.get("totalReports", 0)),
                details={
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_tor": data.get("isTor"),
                    "usage_type": data.get("usageType"),
                    "last_reported_at": data.get("lastReportedAt"),
                },
            )
        except requests.RequestException as exc:
            logger.exception("AbuseIPDB request failed for %s", ip)
            return EnrichmentResult(
                ioc_type="ipv4", value=ip, provider="abuseipdb", score=0,
                error=str(exc),
            )

    # -- Hash enrichment (VirusTotal) ----------------------------------------

    def _enrich_hash(self, file_hash: str) -> EnrichmentResult:
        ioc_type = "sha256" if len(file_hash) == 64 else "md5"

        if self.test_mode or not self.vt_api_key:
            return self._mock_hash_result(file_hash, ioc_type)

        self.vt_rate_limiter.acquire()
        try:
            response = _request_with_backoff(
                "GET",
                f"{self.vt_base_url}/files/{file_hash}",
                headers={"x-apikey": self.vt_api_key},
                timeout=self.vt_timeout,
                max_retries=self.vt_max_retries,
                backoff_base=self.vt_backoff_base,
                backoff_max=self.vt_backoff_max,
            )
            if response.status_code == 404:
                return EnrichmentResult(
                    ioc_type=ioc_type, value=file_hash, provider="virustotal",
                    score=0, details={"note": "Not found in VirusTotal dataset"},
                )
            if response.status_code != 200:
                logger.error("VirusTotal error %s for %s", response.status_code, file_hash)
                return EnrichmentResult(
                    ioc_type=ioc_type, value=file_hash, provider="virustotal", score=0,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(stats.values()) if stats else 0
            score = int(round(((malicious + suspicious) / total) * 100)) if total else 0
            return EnrichmentResult(
                ioc_type=ioc_type,
                value=file_hash,
                provider="virustotal",
                score=score,
                malicious_votes=malicious + suspicious,
                total_votes=total,
                details={
                    "type_description": attrs.get("type_description"),
                    "meaningful_name": attrs.get("meaningful_name"),
                    "popular_threat_classification": attrs.get(
                        "popular_threat_classification", {}
                    ).get("suggested_threat_label"),
                    "last_analysis_stats": stats,
                },
            )
        except requests.RequestException as exc:
            logger.exception("VirusTotal request failed for %s", file_hash)
            return EnrichmentResult(
                ioc_type=ioc_type, value=file_hash, provider="virustotal", score=0,
                error=str(exc),
            )

    # -- Domain enrichment (VirusTotal) --------------------------------------

    def _enrich_domain(self, domain: str) -> EnrichmentResult:
        if self.test_mode or not self.vt_api_key:
            return self._mock_domain_result(domain)

        self.vt_rate_limiter.acquire()
        try:
            response = _request_with_backoff(
                "GET",
                f"{self.vt_base_url}/domains/{domain}",
                headers={"x-apikey": self.vt_api_key},
                timeout=self.vt_timeout,
                max_retries=self.vt_max_retries,
                backoff_base=self.vt_backoff_base,
                backoff_max=self.vt_backoff_max,
            )
            if response.status_code != 200:
                logger.error("VirusTotal error %s for %s", response.status_code, domain)
                return EnrichmentResult(
                    ioc_type="domain", value=domain, provider="virustotal", score=0,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(stats.values()) if stats else 0
            score = int(round(((malicious + suspicious) / total) * 100)) if total else 0
            return EnrichmentResult(
                ioc_type="domain",
                value=domain,
                provider="virustotal",
                score=score,
                malicious_votes=malicious + suspicious,
                total_votes=total,
                details={
                    "categories": attrs.get("categories"),
                    "reputation": attrs.get("reputation"),
                    "last_analysis_stats": stats,
                },
            )
        except requests.RequestException as exc:
            logger.exception("VirusTotal request failed for %s", domain)
            return EnrichmentResult(
                ioc_type="domain", value=domain, provider="virustotal", score=0,
                error=str(exc),
            )

    # -- Mock mode generators --------------------------------------------------
    # Deterministic (hash-seeded) so repeated runs against the same IOC value
    # produce the same simulated verdict -- useful for reproducible demos/tests.

    @staticmethod
    def _deterministic_seed(value: str) -> int:
        return int(hashlib.sha256(value.encode()).hexdigest(), 16)

    def _mock_ip_result(self, ip: str) -> EnrichmentResult:
        seed = self._deterministic_seed(ip)
        rng = random.Random(seed)

        # Known-bad sample IPs from our sample_logs.json are pinned to
        # realistic malicious scores so the demo output is illustrative.
        pinned = {
            "203.0.113.55": 92,   # brute-force source
            "198.51.100.77": 87,  # C2 beacon destination
            "198.51.100.201": 65, # port scan source
        }
        score = pinned.get(ip, rng.randint(0, 15))

        return EnrichmentResult(
            ioc_type="ipv4",
            value=ip,
            provider="abuseipdb (mock)",
            score=score,
            malicious_votes=rng.randint(1, 50) if score > 0 else 0,
            total_votes=rng.randint(50, 200),
            details={
                "country_code": rng.choice(["RU", "CN", "US", "NL", "BR", "IR"]),
                "isp": "Simulated-ISP-Networks",
                "is_tor": score > 80 and rng.random() > 0.6,
                "usage_type": "Data Center/Web Hosting/Transit",
                "mock_mode": True,
            },
        )

    def _mock_hash_result(self, file_hash: str, ioc_type: str) -> EnrichmentResult:
        seed = self._deterministic_seed(file_hash)
        rng = random.Random(seed)

        pinned = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85": 96,
            "5d41402abc4b2a76b9719d911017c592": 88,
        }
        score = pinned.get(file_hash, rng.randint(0, 10))
        total = 70
        malicious = int(round(score / 100 * total))

        return EnrichmentResult(
            ioc_type=ioc_type,
            value=file_hash,
            provider="virustotal (mock)",
            score=score,
            malicious_votes=malicious,
            total_votes=total,
            details={
                "type_description": "Win32 EXE" if score > 50 else "Unknown",
                "popular_threat_classification": (
                    "trojan.generic/malgent" if score > 50 else None
                ),
                "mock_mode": True,
            },
        )

    def _mock_domain_result(self, domain: str) -> EnrichmentResult:
        seed = self._deterministic_seed(domain)
        rng = random.Random(seed)

        pinned = {
            "malicious-c2-server.badnet": 90,
            "cdn-update-service.xyz": 83,
        }
        score = pinned.get(domain, rng.randint(0, 12))
        total = 90
        malicious = int(round(score / 100 * total))

        return EnrichmentResult(
            ioc_type="domain",
            value=domain,
            provider="virustotal (mock)",
            score=score,
            malicious_votes=malicious,
            total_votes=total,
            details={
                "categories": {"mock_engine": "command-and-control"} if score > 50 else {},
                "reputation": -60 if score > 50 else 5,
                "mock_mode": True,
            },
        )
