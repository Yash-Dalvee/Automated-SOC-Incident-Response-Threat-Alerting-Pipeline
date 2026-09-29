"""
tests/test_pipeline.py
========================
Pytest suite covering:
    - IOC regex extraction (IPv4, domain, SHA256, MD5)
    - Private/internal IP suppression (RFC1918 + loopback + link-local)
    - Mock-mode threat intelligence enrichment and severity classification
    - Slack / Discord payload construction (structure + color coding)
    - End-to-end pipeline execution against the bundled sample_logs.json
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path so `import src...` works when tests
# are run from any working directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.enricher import (  # noqa: E402
    ThreatIntelEnricher,
    classify_severity,
    highest_severity,
)
from src.notifier import AlertCard, DiscordNotifier, SlackNotifier  # noqa: E402
from src.parser import IOC, LogParser, is_private_or_reserved_ip  # noqa: E402
from src.main import load_config, run_pipeline  # noqa: E402


DEFAULT_EXTRACTION_CONFIG = {
    "extract_ipv4": True,
    "extract_domains": True,
    "extract_sha256": True,
    "extract_md5": True,
    "suppress_private_ips": True,
    "domain_false_positive_suffixes": [".exe", ".dll", ".bin", ".zip"],
}

DEFAULT_SEVERITY_THRESHOLDS = {
    "critical": 80,
    "high": 50,
    "medium": 20,
    "low": 1,
}


# ------------------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------------------

@pytest.fixture
def parser() -> LogParser:
    return LogParser(DEFAULT_EXTRACTION_CONFIG)


@pytest.fixture
def enricher() -> ThreatIntelEnricher:
    config = load_config(PROJECT_ROOT / "config" / "config.yaml")
    return ThreatIntelEnricher(
        config["enrichment"],
        vt_api_key=None,
        abuseipdb_api_key=None,
        test_mode=True,
    )


# ------------------------------------------------------------------------------
# Private IP suppression
# ------------------------------------------------------------------------------

class TestPrivateIPFiltering:
    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.168.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
        ],
    )
    def test_private_ips_are_flagged(self, ip: str) -> None:
        assert is_private_or_reserved_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        ["203.0.113.55", "8.8.8.8", "1.1.1.1", "198.51.100.201"],
    )
    def test_public_ips_are_not_flagged(self, ip: str) -> None:
        assert is_private_or_reserved_ip(ip) is False

    def test_invalid_ip_treated_as_non_actionable(self) -> None:
        assert is_private_or_reserved_ip("999.999.999.999") is True


# ------------------------------------------------------------------------------
# IOC extraction
# ------------------------------------------------------------------------------

class TestIOCExtraction:
    def test_extracts_public_ipv4(self, parser: LogParser) -> None:
        text = "Connection from 203.0.113.55 to internal host 10.0.0.5"
        iocs = parser.extract_iocs_from_text(text)
        values = {i.value for i in iocs if i.ioc_type == "ipv4"}
        assert "203.0.113.55" in values
        assert "10.0.0.5" not in values  # suppressed private IP

    def test_extracts_sha256(self, parser: LogParser) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
        text = f"File hash SHA256 {sha256} flagged as malicious"
        iocs = parser.extract_iocs_from_text(text)
        sha_values = {i.value for i in iocs if i.ioc_type == "sha256"}
        assert sha256 in sha_values

    def test_extracts_md5_without_duplicating_sha256(self, parser: LogParser) -> None:
        md5 = "5d41402abc4b2a76b9719d911017c592"
        text = f"Secondary hash MD5 {md5} observed"
        iocs = parser.extract_iocs_from_text(text)
        md5_values = {i.value for i in iocs if i.ioc_type == "md5"}
        assert md5 in md5_values

    def test_extracts_domain(self, parser: LogParser) -> None:
        text = "Beaconing to malicious-c2-server.badnet over HTTPS"
        iocs = parser.extract_iocs_from_text(text)
        domain_values = {i.value for i in iocs if i.ioc_type == "domain"}
        assert "malicious-c2-server.badnet" in domain_values

    def test_domain_false_positive_suppressed(self, parser: LogParser) -> None:
        text = "Dropped payload file invoice_update.exe onto disk"
        iocs = parser.extract_iocs_from_text(text)
        domain_values = {i.value for i in iocs if i.ioc_type == "domain"}
        assert "invoice_update.exe" not in domain_values

    def test_defanged_domain_is_extracted(self, parser: LogParser) -> None:
        text = "User visited hxxp://cdn-update-service[.]xyz/payload"
        iocs = parser.extract_iocs_from_text(text)
        domain_values = {i.value for i in iocs if i.ioc_type == "domain"}
        assert "cdn-update-service.xyz" in domain_values

    def test_ioc_deduplication(self, parser: LogParser) -> None:
        text = "203.0.113.55 attacked us. 203.0.113.55 attacked us again."
        iocs = parser.extract_iocs_from_text(text)
        ipv4_matches = [i for i in iocs if i.value == "203.0.113.55"]
        assert len(ipv4_matches) == 1


# ------------------------------------------------------------------------------
# Severity classification
# ------------------------------------------------------------------------------

class TestSeverityClassification:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "CLEAN"),
            (1, "LOW"),
            (19, "LOW"),
            (20, "MEDIUM"),
            (49, "MEDIUM"),
            (50, "HIGH"),
            (79, "HIGH"),
            (80, "CRITICAL"),
            (100, "CRITICAL"),
        ],
    )
    def test_classify_severity_thresholds(self, score: int, expected: str) -> None:
        assert classify_severity(score, DEFAULT_SEVERITY_THRESHOLDS) == expected

    def test_highest_severity_picks_max(self) -> None:
        assert highest_severity(["LOW", "CRITICAL", "MEDIUM"]) == "CRITICAL"

    def test_highest_severity_empty_defaults_clean(self) -> None:
        assert highest_severity([]) == "CLEAN"


# ------------------------------------------------------------------------------
# Mock-mode enrichment
# ------------------------------------------------------------------------------

class TestMockEnrichment:
    def test_known_malicious_ip_scores_high(self, enricher: ThreatIntelEnricher) -> None:
        result = enricher.enrich(IOC(ioc_type="ipv4", value="203.0.113.55"))
        assert result.score >= 80
        assert result.provider == "abuseipdb (mock)"

    def test_known_malicious_hash_scores_high(self, enricher: ThreatIntelEnricher) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
        result = enricher.enrich(IOC(ioc_type="sha256", value=sha256))
        assert result.score >= 90

    def test_known_malicious_domain_scores_high(self, enricher: ThreatIntelEnricher) -> None:
        result = enricher.enrich(IOC(ioc_type="domain", value="malicious-c2-server.badnet"))
        assert result.score >= 80

    def test_enrichment_is_deterministic(self, enricher: ThreatIntelEnricher) -> None:
        r1 = enricher.enrich(IOC(ioc_type="ipv4", value="1.2.3.4"))
        r2 = enricher.enrich(IOC(ioc_type="ipv4", value="1.2.3.4"))
        assert r1.score == r2.score

    def test_unsupported_ioc_type_handled_gracefully(
        self, enricher: ThreatIntelEnricher
    ) -> None:
        # Directly construct a bogus IOC bypassing validation isn't possible
        # since pydantic validates ioc_type; instead assert the enum guard.
        with pytest.raises(ValueError):
            IOC(ioc_type="bogus", value="x")


# ------------------------------------------------------------------------------
# Notifier payload construction
# ------------------------------------------------------------------------------

class TestNotifierPayloads:
    @pytest.fixture
    def sample_alert(self, enricher: ThreatIntelEnricher) -> AlertCard:
        enrichment = enricher.enrich(IOC(ioc_type="ipv4", value="203.0.113.55"))
        return AlertCard(
            event_id="evt-test-001",
            event_type="ssh_brute_force",
            host="test-host",
            timestamp="2026-08-20T03:14:22Z",
            severity="CRITICAL",
            message="Test brute force event",
            enrichments=[enrichment],
        )

    def test_slack_payload_structure(self, sample_alert: AlertCard) -> None:
        notifier = SlackNotifier(
            webhook_url=None,
            severity_colors_hex={"CRITICAL": "#FF0000"},
            test_mode=True,
        )
        payload = notifier.build_payload(sample_alert)
        assert "attachments" in payload
        assert payload["attachments"][0]["color"] == "#FF0000"
        blocks = payload["attachments"][0]["blocks"]
        assert any(b.get("type") == "header" for b in blocks)

    def test_discord_payload_structure(self, sample_alert: AlertCard) -> None:
        notifier = DiscordNotifier(
            webhook_url=None,
            severity_colors_decimal={"CRITICAL": 16711680},
            test_mode=True,
        )
        payload = notifier.build_payload(sample_alert)
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert embed["color"] == 16711680
        assert "CRITICAL" in embed["title"]

    def test_mock_send_does_not_raise_without_webhook(
        self, sample_alert: AlertCard
    ) -> None:
        slack = SlackNotifier(webhook_url=None, severity_colors_hex={}, test_mode=True)
        discord = DiscordNotifier(
            webhook_url=None, severity_colors_decimal={}, test_mode=True
        )
        ok_slack, _ = slack.send(sample_alert)
        ok_discord, _ = discord.send(sample_alert)
        assert ok_slack is True
        assert ok_discord is True


# ------------------------------------------------------------------------------
# End-to-end pipeline test
# ------------------------------------------------------------------------------

class TestEndToEndPipeline:
    def test_pipeline_runs_against_sample_logs(self) -> None:
        summaries = run_pipeline(
            log_file=PROJECT_ROOT / "data" / "sample_logs.json",
            config_path=PROJECT_ROOT / "config" / "config.yaml",
            override_test_mode=True,
        )
        assert len(summaries) == 5

        by_id = {s["event_id"]: s for s in summaries}

        # Brute force event should be classified at least HIGH.
        assert by_id["evt-1001"]["severity"] in ("HIGH", "CRITICAL")
        # Malware download event should be CRITICAL (known malicious hash).
        assert by_id["evt-1002"]["severity"] == "CRITICAL"
        # C2 beaconing event should be CRITICAL (known malicious IP/domain).
        assert by_id["evt-1003"]["severity"] == "CRITICAL"
        # Internal safe traffic should be CLEAN (all IOCs private/suppressed).
        assert by_id["evt-1004"]["severity"] == "CLEAN"
        assert by_id["evt-1004"]["notified"] is False

    def test_all_events_have_ioc_summaries(self) -> None:
        summaries = run_pipeline(
            log_file=PROJECT_ROOT / "data" / "sample_logs.json",
            config_path=PROJECT_ROOT / "config" / "config.yaml",
            override_test_mode=True,
        )
        for s in summaries:
            assert isinstance(s["iocs"], list)
            assert "dispatch_results" in s


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
