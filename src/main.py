"""
src/main.py
============
Orchestrates the full SOC Incident Response pipeline:

    1. Load configuration (config/config.yaml) + secrets (.env)
    2. Parse log telemetry (JSON events) and extract IOCs
    3. Enrich each IOC via VirusTotal / AbuseIPDB (or mock mode)
    4. Classify event severity from the highest-scoring IOC
    5. Dispatch color-coded alert cards to Slack / Discord when the
       configured severity threshold is met or exceeded

Run directly:
    python -m src.main --log-file data/sample_logs.json

Or import `run_pipeline(...)` programmatically.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from src.enricher import (
    SEVERITY_ORDER,
    ThreatIntelEnricher,
    classify_severity,
    highest_severity,
)
from src.notifier import AlertCard, AlertDispatcher, DiscordNotifier, SlackNotifier
from src.parser import LogParser

logger = logging.getLogger("soc_ir_pipeline.main")


# ------------------------------------------------------------------------------
# Configuration loading
# ------------------------------------------------------------------------------

def load_config(config_path: str | Path) -> dict[str, Any]:
    """Loads and returns the pipeline YAML configuration as a dict."""
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


# ------------------------------------------------------------------------------
# Pipeline
# ------------------------------------------------------------------------------

def run_pipeline(
    log_file: str | Path,
    config_path: str | Path = "config/config.yaml",
    override_test_mode: bool | None = None,
) -> list[dict[str, Any]]:
    """
    Executes the end-to-end pipeline against a JSON log file and returns a
    list of summary dicts (one per processed event) describing the outcome.
    """
    load_dotenv()
    config = load_config(config_path)

    pipeline_cfg = config.get("pipeline", {})
    configure_logging(pipeline_cfg.get("log_level", "INFO"))

    test_mode = pipeline_cfg.get("test_mode", True)
    if override_test_mode is not None:
        test_mode = override_test_mode

    logger.info(
        "Starting %s v%s (test_mode=%s)",
        pipeline_cfg.get("name", "SOC IR Pipeline"),
        pipeline_cfg.get("version", "0.0.0"),
        test_mode,
    )

    # -- Secrets from environment --------------------------------------------
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
    slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    # -- Build pipeline components --------------------------------------------
    parser = LogParser(config.get("extraction", {}))
    enricher = ThreatIntelEnricher(
        config.get("enrichment", {}),
        vt_api_key=vt_api_key,
        abuseipdb_api_key=abuseipdb_api_key,
        test_mode=test_mode,
    )

    alerting_cfg = config.get("alerting", {})
    slack_notifier = None
    if alerting_cfg.get("slack", {}).get("enabled", True):
        slack_notifier = SlackNotifier(
            webhook_url=slack_webhook_url,
            severity_colors_hex=alerting_cfg.get("severity_colors", {}),
            test_mode=test_mode,
        )

    discord_notifier = None
    if alerting_cfg.get("discord", {}).get("enabled", True):
        discord_notifier = DiscordNotifier(
            webhook_url=discord_webhook_url,
            severity_colors_decimal=alerting_cfg.get("severity_colors_decimal", {}),
            test_mode=test_mode,
        )

    dispatcher = AlertDispatcher(slack_notifier, discord_notifier)

    severity_thresholds = config.get("severity_thresholds", {})
    min_severity = alerting_cfg.get("minimum_severity_to_notify", "LOW")
    min_severity_rank = SEVERITY_ORDER.index(min_severity)

    # -- Parse & extract --------------------------------------------------------
    events = parser.load_json_file(log_file)

    summaries: list[dict[str, Any]] = []

    for event in events:
        logger.info(
            "Processing event %s (%s) on host %s -- %d IOC(s) extracted",
            event.event_id, event.event_type, event.host, len(event.iocs),
        )

        enrichments = enricher.enrich_many(event.iocs)
        event_severities = [
            classify_severity(e.score, severity_thresholds) for e in enrichments
        ]
        overall_severity = highest_severity(event_severities)

        notified = False
        dispatch_results: dict[str, tuple[bool, str]] = {}

        if SEVERITY_ORDER.index(overall_severity) >= min_severity_rank:
            alert = AlertCard(
                event_id=event.event_id,
                event_type=event.event_type or "unknown",
                host=event.host or "unknown",
                timestamp=event.timestamp or "",
                severity=overall_severity,
                message=event.message,
                enrichments=enrichments,
            )
            dispatch_results = dispatcher.dispatch(alert)
            notified = True
            logger.info(
                "Event %s classified %s -- alert dispatched: %s",
                event.event_id, overall_severity, dispatch_results,
            )
        else:
            logger.info(
                "Event %s classified %s -- below notification threshold (%s), skipping",
                event.event_id, overall_severity, min_severity,
            )

        summaries.append(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "host": event.host,
                "severity": overall_severity,
                "ioc_count": len(event.iocs),
                "iocs": [
                    {
                        "type": e.ioc_type,
                        "value": e.value,
                        "score": e.score,
                        "provider": e.provider,
                    }
                    for e in enrichments
                ],
                "notified": notified,
                "dispatch_results": {
                    channel: {"success": ok, "detail": detail}
                    for channel, (ok, detail) in dispatch_results.items()
                },
            }
        )

    logger.info("Pipeline run complete. Processed %d event(s).", len(summaries))
    return summaries


# ------------------------------------------------------------------------------
# CLI entrypoint
# ------------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-ir-pipeline",
        description="Automated SOC Incident Response & Threat Alerting Pipeline",
    )
    parser.add_argument(
        "--log-file",
        default="data/sample_logs.json",
        help="Path to the JSON log telemetry file (default: data/sample_logs.json)",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to the pipeline YAML configuration file",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Force live API/webhook calls, overriding config test_mode=true",
    )
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="Force mock mode, overriding config test_mode=false",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()

    override: bool | None = None
    if args.live and args.test_mode:
        print("Error: --live and --test-mode are mutually exclusive.", file=sys.stderr)
        sys.exit(2)
    elif args.live:
        override = False
    elif args.test_mode:
        override = True

    summaries = run_pipeline(
        log_file=args.log_file,
        config_path=args.config,
        override_test_mode=override,
    )

    print("\n" + "=" * 78)
    print("PIPELINE RUN SUMMARY")
    print("=" * 78)
    for s in summaries:
        print(
            f"[{s['severity']:>8}] {s['event_id']:<12} "
            f"{s['event_type']:<24} host={s['host']:<20} "
            f"iocs={s['ioc_count']} notified={s['notified']}"
        )
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
