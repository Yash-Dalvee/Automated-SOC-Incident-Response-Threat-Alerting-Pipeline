"""
src/parser.py
==============
Log ingestion and Indicator of Compromise (IOC) extraction.

Supports two input formats:
    1. JSON array of structured log event objects (as produced by SIEM
       exports, EDR platforms, or custom log shippers).
    2. Raw syslog lines (RFC3164-style), one event per line.

Extracts IPv4 addresses, domain names, SHA256 hashes, and MD5 hashes from
free-text log fields using regular expressions, and filters out private /
internal / non-routable IP addresses (RFC1918, loopback, link-local, etc.)
so that only externally-relevant indicators are enriched and alerted on.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("soc_ir_pipeline.parser")

# ------------------------------------------------------------------------------
# Regular expressions for IOC extraction
# ------------------------------------------------------------------------------

# Matches valid dotted-quad IPv4 addresses (0-255 per octet).
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Matches SHA256 hex digests (64 hex chars) - checked before MD5 due to length.
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Matches MD5 hex digests (32 hex chars).
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Matches generic domain names (label.label.tld). Applied AFTER hash/IP
# extraction and filtered to remove overlaps / false positives.
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

# Common "defanged" indicator patterns seen in SOC/threat-intel logs, e.g.
# hxxp://, hxxps://, [.] instead of a literal dot. We normalize these before
# running extraction so they are matched correctly.
_DEFANG_REPLACEMENTS = (
    (re.compile(r"hxxps?://", re.IGNORECASE), "http://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
)


def _normalize_defanged(text: str) -> str:
    """Re-fangs common defanged indicator notations for reliable regex matching."""
    for pattern, replacement in _DEFANG_REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return text


# ------------------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------------------

class IOC(BaseModel):
    """A single extracted Indicator of Compromise."""

    ioc_type: str = Field(..., description="One of: ipv4, domain, sha256, md5")
    value: str

    @field_validator("ioc_type")
    @classmethod
    def _validate_type(cls, v: str) -> str:
        allowed = {"ipv4", "domain", "sha256", "md5"}
        if v not in allowed:
            raise ValueError(f"ioc_type must be one of {allowed}, got {v!r}")
        return v

    def __hash__(self) -> int:
        return hash((self.ioc_type, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IOC):
            return NotImplemented
        return self.ioc_type == other.ioc_type and self.value == other.value


class LogEvent(BaseModel):
    """A normalized security log event ready for enrichment."""

    event_id: str
    timestamp: str | None = None
    source: str | None = None
    event_type: str | None = None
    host: str | None = None
    message: str
    raw_syslog: str | None = None
    iocs: list[IOC] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# IP filtering
# ------------------------------------------------------------------------------

# Explicit internal-use / non-routable IPv4 ranges to suppress. We deliberately
# do NOT use Python's blanket `ipaddress.is_private`/`is_reserved` attributes,
# because those also classify RFC 5737 documentation/example ranges (e.g.
# 198.51.100.0/24, 203.0.113.0/24 -- commonly used to represent illustrative
# "public" attacker infrastructure in logs, docs, and this project's own
# sample data) as private. That blanket behavior would incorrectly suppress
# legitimate external threat indicators. Instead we suppress only ranges that
# are genuinely internal-network / non-internet-routable in real deployments.
_SUPPRESSED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local (APIPA)
    ipaddress.ip_network("0.0.0.0/8"),        # "This network"
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
]


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """
    Returns True if the given IPv4 string falls within RFC1918 private space,
    loopback, link-local, multicast, or broadcast ranges -- i.e. an internal
    address that should never be sent to external threat-intel APIs.

    Public/documentation-range addresses (including RFC 5737 TEST-NET ranges
    used in example logs) are intentionally NOT suppressed here, since in a
    real deployment they represent externally-routable or illustrative
    attacker infrastructure that IS worth enriching.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # Not a valid IP at all -> treat as non-actionable.

    return any(addr in network for network in _SUPPRESSED_NETWORKS)


# ------------------------------------------------------------------------------
# Extraction logic
# ------------------------------------------------------------------------------

class LogParser:
    """
    Parses raw log input (JSON events or syslog lines) into LogEvent objects
    and extracts IOCs from each event's textual content according to the
    rules defined in the pipeline configuration.
    """

    def __init__(self, extraction_config: dict[str, Any] | None = None):
        cfg = extraction_config or {}
        self.extract_ipv4 = cfg.get("extract_ipv4", True)
        self.extract_domains = cfg.get("extract_domains", True)
        self.extract_sha256 = cfg.get("extract_sha256", True)
        self.extract_md5 = cfg.get("extract_md5", True)
        self.suppress_private_ips = cfg.get("suppress_private_ips", True)
        self.domain_false_positive_suffixes = tuple(
            s.lower() for s in cfg.get("domain_false_positive_suffixes", [])
        )
        self.domain_internal_suffixes = tuple(
            s.lower() for s in cfg.get("domain_internal_suffixes", [])
        )

    # -- Loading -----------------------------------------------------------

    def load_json_file(self, path: str | Path) -> list[LogEvent]:
        """Loads a JSON array of log events from disk and normalizes them."""
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            raw_events: list[dict[str, Any]] = json.load(fh)

        events: list[LogEvent] = []
        for raw in raw_events:
            event = LogEvent(**raw)
            self.extract_iocs_for_event(event)
            events.append(event)

        logger.info("Loaded %d log events from %s", len(events), path)
        return events

    def parse_syslog_lines(self, lines: Iterable[str]) -> list[LogEvent]:
        """
        Parses raw RFC3164-style syslog lines into LogEvent objects.
        Each line becomes its own event; the full line is used as the
        message body for IOC extraction.
        """
        events: list[LogEvent] = []
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            event = LogEvent(
                event_id=f"syslog-{idx:04d}",
                message=line,
                raw_syslog=line,
                source="syslog",
            )
            self.extract_iocs_for_event(event)
            events.append(event)

        logger.info("Parsed %d syslog lines", len(events))
        return events

    # -- Extraction ----------------------------------------------------------

    def extract_iocs_for_event(self, event: LogEvent) -> list[IOC]:
        """Extracts and attaches IOCs to a LogEvent in-place, returning them."""
        combined_text = " ".join(
            filter(None, [event.message, event.raw_syslog or ""])
        )
        iocs = self.extract_iocs_from_text(combined_text)
        event.iocs = iocs
        return iocs

    def extract_iocs_from_text(self, text: str) -> list[IOC]:
        """
        Runs all enabled IOC extractors against a block of free text and
        returns a de-duplicated list of IOC objects.
        """
        text = _normalize_defanged(text)
        found: dict[tuple[str, str], IOC] = {}

        # Hashes first (longest match wins - SHA256 before MD5 to avoid a
        # 64-char hash also accidentally matching as two 32-char chunks).
        sha256_matches = set()
        if self.extract_sha256:
            for m in SHA256_REGEX.finditer(text):
                value = m.group(0).lower()
                sha256_matches.add(value)
                found[("sha256", value)] = IOC(ioc_type="sha256", value=value)

        if self.extract_md5:
            for m in MD5_REGEX.finditer(text):
                value = m.group(0).lower()
                # Skip if this 32-char span is actually a substring of an
                # already-matched 64-char SHA256 (defensive; regex word
                # boundaries make this rare but not impossible).
                if any(value in sha for sha in sha256_matches):
                    continue
                found[("md5", value)] = IOC(ioc_type="md5", value=value)

        ipv4_matches = set()
        if self.extract_ipv4:
            for m in IPV4_REGEX.finditer(text):
                value = m.group(0)
                if self.suppress_private_ips and is_private_or_reserved_ip(value):
                    logger.debug("Suppressing private/reserved IP: %s", value)
                    continue
                ipv4_matches.add(value)
                found[("ipv4", value)] = IOC(ioc_type="ipv4", value=value)

        if self.extract_domains:
            for m in DOMAIN_REGEX.finditer(text):
                raw_value = m.group(0)
                value = raw_value.lower()
                if self._is_domain_false_positive(value, ipv4_matches, raw_value):
                    continue
                found[("domain", value)] = IOC(ioc_type="domain", value=value)

        return list(found.values())

    # Every label is "Titlecase" (capital + lowercase) -- a strong signal
    # that the match is prose (e.g. "Trojan.Generic", "Windows.Update")
    # rather than an actual hostname, which is conventionally all-lowercase.
    _TITLECASE_PROSE_REGEX = re.compile(r"^(?:[A-Z][a-z]+\.)+[A-Z][a-z]+$")

    def _is_domain_false_positive(
        self, value: str, ipv4_matches: set[str], raw_value: str
    ) -> bool:
        """
        Filters out domain-regex matches that are actually IP addresses,
        file names with extensions, prose sentence-case phrases (e.g. threat
        classification labels like "Trojan.Generic"), or otherwise not
        meaningful domains.
        """
        # Already captured as an IP address elsewhere.
        if value in ipv4_matches:
            return True
        # Looks like a bare IPv4 (all-numeric octets) even if not in our
        # already-found IP set (e.g. suppressed private IP).
        octets = value.split(".")
        if all(part.isdigit() for part in octets):
            return True
        # Known file-extension false positives (e.g. "invoice_update.exe").
        if value.endswith(self.domain_false_positive_suffixes):
            return True
        # Internal-use / non-internet-routable domain suffixes (e.g.
        # "intranet.corp.local") -- never worth sending to external TI APIs.
        if value.endswith(self.domain_internal_suffixes):
            return True
        # Sentence-case prose masquerading as a dotted hostname.
        if self._TITLECASE_PROSE_REGEX.match(raw_value):
            return True
        return False


# ------------------------------------------------------------------------------
# Convenience module-level function
# ------------------------------------------------------------------------------

def extract_all_iocs(events: list[LogEvent]) -> list[IOC]:
    """Flattens and de-duplicates IOCs across a list of LogEvents."""
    seen: dict[tuple[str, str], IOC] = {}
    for event in events:
        for ioc in event.iocs:
            seen[(ioc.ioc_type, ioc.value)] = ioc
    return list(seen.values())
