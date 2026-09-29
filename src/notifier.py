"""
src/notifier.py
=================
Rich, color-coded alert dispatch to Slack (Block Kit + attachment color bar)
and Discord (Embeds) webhooks.

Both notifiers:
    - Build a structured "AlertCard" summarizing the triggering event, its
      severity, and every enriched IOC.
    - Retry transient failures with exponential backoff.
    - Support a mock/test mode that logs the payload instead of performing
      a real HTTP POST, so the pipeline can be demoed without live webhooks.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from src.enricher import EnrichmentResult

logger = logging.getLogger("soc_ir_pipeline.notifier")

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "CLEAN": "🟢",
}


@dataclass
class AlertCard:
    """Structured representation of a single incident alert, provider-agnostic."""

    event_id: str
    event_type: str
    host: str
    timestamp: str
    severity: str
    message: str
    enrichments: list[EnrichmentResult] = field(default_factory=list)


# ------------------------------------------------------------------------------
# Shared HTTP dispatch helper (retry + backoff)
# ------------------------------------------------------------------------------

def _post_with_backoff(
    url: str,
    json_payload: dict[str, Any],
    *,
    max_retries: int = 4,
    backoff_base: float = 1.5,
    timeout: int = 10,
) -> tuple[bool, str]:
    """
    POSTs a JSON payload with exponential backoff on 429/5xx/connection
    errors. Returns (success, message).
    """
    last_error = "unknown error"
    for attempt in range(max_retries):
        try:
            response = requests.post(url, json=json_payload, timeout=timeout)
            if response.status_code in (200, 204):
                return True, f"HTTP {response.status_code}"
            if response.status_code == 429 or response.status_code >= 500:
                delay = backoff_base * (2 ** attempt)
                logger.warning(
                    "Webhook transient failure HTTP %s, retrying in %.1fs",
                    response.status_code, delay,
                )
                time.sleep(delay)
                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                continue
            # Non-retryable client error (4xx other than 429).
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except requests.RequestException as exc:
            last_error = str(exc)
            delay = backoff_base * (2 ** attempt)
            logger.warning("Webhook request error: %s, retrying in %.1fs", exc, delay)
            time.sleep(delay)

    return False, f"Exhausted retries: {last_error}"


# ------------------------------------------------------------------------------
# Slack notifier (Block Kit)
# ------------------------------------------------------------------------------

class SlackNotifier:
    """Sends alert cards to a Slack Incoming Webhook using Block Kit + color bar."""

    def __init__(
        self,
        webhook_url: str | None,
        severity_colors_hex: dict[str, str],
        test_mode: bool = True,
    ):
        self.webhook_url = webhook_url
        self.severity_colors_hex = severity_colors_hex
        self.test_mode = test_mode

    def build_payload(self, alert: AlertCard) -> dict[str, Any]:
        emoji = SEVERITY_EMOJI.get(alert.severity, "⚪")
        color = self.severity_colors_hex.get(alert.severity, "#808080")

        header_blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {alert.severity} Severity Alert",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event ID:*\n{alert.event_id}"},
                    {"type": "mrkdwn", "text": f"*Event Type:*\n{alert.event_type}"},
                    {"type": "mrkdwn", "text": f"*Host:*\n{alert.host}"},
                    {"type": "mrkdwn", "text": f"*Timestamp:*\n{alert.timestamp}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{alert.message}"},
            },
            {"type": "divider"},
        ]

        ioc_blocks: list[dict[str, Any]] = []
        for enrichment in alert.enrichments:
            ioc_blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*{enrichment.ioc_type.upper()}:* `{enrichment.value}`\n"
                            f"Score: *{enrichment.score}/100*  |  "
                            f"Provider: {enrichment.provider}  |  "
                            f"Votes: {enrichment.malicious_votes}/{enrichment.total_votes}"
                        ),
                    },
                }
            )

        footer_blocks = [
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Automated SOC Incident Response & Threat Alerting Pipeline",
                    }
                ],
            }
        ]

        all_blocks = header_blocks + ioc_blocks + footer_blocks

        # Slack's "color" bar attribute is only honored on legacy attachments,
        # so we wrap the Block Kit blocks in a single colored attachment to
        # get both modern block layout and a severity color strip.
        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": all_blocks,
                }
            ]
        }

    def send(self, alert: AlertCard) -> tuple[bool, str]:
        payload = self.build_payload(alert)

        if self.test_mode or not self.webhook_url:
            logger.info(
                "[MOCK SLACK SEND] event=%s severity=%s iocs=%d",
                alert.event_id, alert.severity, len(alert.enrichments),
            )
            return True, "mock_mode: payload built but not sent"

        success, detail = _post_with_backoff(self.webhook_url, payload)
        if success:
            logger.info("Slack alert sent for event %s", alert.event_id)
        else:
            logger.error("Slack alert FAILED for event %s: %s", alert.event_id, detail)
        return success, detail


# ------------------------------------------------------------------------------
# Discord notifier (Embeds)
# ------------------------------------------------------------------------------

class DiscordNotifier:
    """Sends alert cards to a Discord Webhook using rich embeds."""

    def __init__(
        self,
        webhook_url: str | None,
        severity_colors_decimal: dict[str, int],
        test_mode: bool = True,
    ):
        self.webhook_url = webhook_url
        self.severity_colors_decimal = severity_colors_decimal
        self.test_mode = test_mode

    def build_payload(self, alert: AlertCard) -> dict[str, Any]:
        emoji = SEVERITY_EMOJI.get(alert.severity, "⚪")
        color = self.severity_colors_decimal.get(alert.severity, 8421504)

        fields = [
            {"name": "Event ID", "value": alert.event_id, "inline": True},
            {"name": "Event Type", "value": alert.event_type, "inline": True},
            {"name": "Host", "value": alert.host, "inline": True},
        ]

        for enrichment in alert.enrichments:
            fields.append(
                {
                    "name": f"{enrichment.ioc_type.upper()}: {enrichment.value}",
                    "value": (
                        f"Score **{enrichment.score}/100** via "
                        f"`{enrichment.provider}` "
                        f"({enrichment.malicious_votes}/{enrichment.total_votes} votes)"
                    ),
                    "inline": False,
                }
            )

        embed = {
            "title": f"{emoji} {alert.severity} Severity Alert",
            "description": alert.message,
            "color": color,
            "timestamp": alert.timestamp,
            "fields": fields,
            "footer": {
                "text": "Automated SOC Incident Response & Threat Alerting Pipeline"
            },
        }

        return {"embeds": [embed]}

    def send(self, alert: AlertCard) -> tuple[bool, str]:
        payload = self.build_payload(alert)

        if self.test_mode or not self.webhook_url:
            logger.info(
                "[MOCK DISCORD SEND] event=%s severity=%s iocs=%d",
                alert.event_id, alert.severity, len(alert.enrichments),
            )
            return True, "mock_mode: payload built but not sent"

        success, detail = _post_with_backoff(self.webhook_url, payload)
        if success:
            logger.info("Discord alert sent for event %s", alert.event_id)
        else:
            logger.error("Discord alert FAILED for event %s: %s", alert.event_id, detail)
        return success, detail


# ------------------------------------------------------------------------------
# Combined dispatcher
# ------------------------------------------------------------------------------

class AlertDispatcher:
    """Fan-out dispatcher that sends a single AlertCard to all enabled channels."""

    def __init__(
        self,
        slack_notifier: SlackNotifier | None,
        discord_notifier: DiscordNotifier | None,
    ):
        self.slack_notifier = slack_notifier
        self.discord_notifier = discord_notifier

    def dispatch(self, alert: AlertCard) -> dict[str, tuple[bool, str]]:
        results: dict[str, tuple[bool, str]] = {}
        if self.slack_notifier:
            results["slack"] = self.slack_notifier.send(alert)
        if self.discord_notifier:
            results["discord"] = self.discord_notifier.send(alert)
        return results
