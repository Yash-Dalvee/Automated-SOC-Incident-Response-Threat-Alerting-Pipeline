"""
Automated SOC Incident Response & Threat Alerting Pipeline
============================================================

Modules:
    parser    - Log ingestion and IOC (Indicator of Compromise) extraction.
    enricher  - Threat intelligence enrichment via VirusTotal / AbuseIPDB.
    notifier  - Rich alert dispatch to Slack (Block Kit) and Discord (Embeds).
    main      - Pipeline orchestration and CLI entrypoint.
"""

__version__ = "1.0.0"
__all__ = ["parser", "enricher", "notifier", "main"]
