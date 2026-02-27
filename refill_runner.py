#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
from pathlib import Path

import requests

from auto_pool_maintainer import load_json, run_batch_register, setup_logger


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_cfg = script_dir / "config.json"
    default_log_dir = script_dir / "logs"

    parser = argparse.ArgumentParser(description="Refill runner (register tokens only)")
    parser.add_argument("--config", default=str(default_cfg), help="Config file path")
    parser.add_argument("--tokens", type=int, required=True, help="How many tokens to refill")
    parser.add_argument("--log-dir", default=str(default_log_dir), help="Log directory")
    return parser.parse_args()


def main() -> int:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    args = parse_args()
    if args.tokens <= 0:
        print("tokens must be greater than 0")
        return 2

    config_path = Path(args.config).resolve()
    logger, log_path = setup_logger(Path(args.log_dir).resolve())

    logger.info("=== Refill Task Start ===")
    logger.info("Config: %s", config_path)
    logger.info("Log File: %s", log_path)
    logger.info("Target Tokens: %s", args.tokens)

    if not config_path.exists():
        logger.error("Config file not found: %s", config_path)
        logger.info("=== Refill Task End (Failed) ===")
        return 2

    conf = load_json(config_path)
    try:
        filled, failed, synced = run_batch_register(conf=conf, target_tokens=int(args.tokens), logger=logger)
    except Exception as e:
        logger.error("Refill failed: %s", e)
        logger.info("=== Refill Task End (Failed) ===")
        return 3

    logger.info("Refill summary: success=%s fail=%s synced=%s", filled, failed, synced)
    if filled < int(args.tokens):
        logger.warning("Refill incomplete: expected=%s actual=%s", args.tokens, filled)
        logger.info("=== Refill Task End (Partial) ===")
        return 1

    logger.info("=== Refill Task End (Success) ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
