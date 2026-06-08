#!/usr/bin/env python3
"""SENTINEL CLI entry point."""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
import structlog

from sentinel.config import SentinelConfig


def _configure_logging(log_level: str, log_format: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)

    if log_format == "json":
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(level),
            logger_factory=structlog.PrintLoggerFactory(),
        )
    else:
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="%H:%M:%S"),
                structlog.dev.ConsoleRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(level),
            logger_factory=structlog.PrintLoggerFactory(),
        )
    logging.basicConfig(level=level, handlers=[logging.NullHandler()])


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config", "-c",
    default="config/sentinel.yaml",
    show_default=True,
    help="Path to YAML configuration file.",
)
@click.option(
    "--mode",
    type=click.Choice(["simulation", "live"]),
    default=None,
    help="Override config mode (simulation|live).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=None,
    help="Override enforcement dry-run flag.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable DEBUG logging.",
)
@click.version_option("1.0.0", prog_name="sentinel")
def main(config: str, mode: str | None, dry_run: bool | None, verbose: bool) -> None:
    """SENTINEL — eBPF + LLM Intent-Based Zero-Trust Anomaly Detection."""
    cfg_path = Path(config)
    if not cfg_path.exists():
        click.echo(f"Config file not found: {config}", err=True)
        sys.exit(1)

    cfg = SentinelConfig.from_yaml(cfg_path)

    if mode is not None:
        cfg.mode = mode  # type: ignore[assignment]
    if dry_run is not None:
        cfg.enforcement.dry_run = dry_run
    if verbose:
        cfg.log_level = "DEBUG"

    _configure_logging(cfg.log_level, cfg.log_format)

    # SentinelAgent orchestrates BPF/simulation I/O and delegates detection to
    # AgentPipeline (Detector → Analyzer → Auditor, Option A hybrid stack).
    from sentinel.agent import SentinelAgent
    agent = SentinelAgent(cfg)
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
