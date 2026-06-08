#!/usr/bin/env python3
"""Merge userspace + eBPF TOCTOU micro-benchmark JSONs into paper artifact."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, "src/python")
from sentinel.provenance import make_meta


def _pct(x: float) -> str:
    return f"{100.0 * x:.1f}\\%"


def main() -> None:
    if len(sys.argv) < 3:
        print(
            "usage: merge_toctou_results.py <out.json> <userspace.json> [ebpf.json] "
            "[red_team_results_gcp.json]",
            file=sys.stderr,
        )
        sys.exit(2)

    out_path = Path(sys.argv[1])
    us = json.loads(Path(sys.argv[2]).read_text())
    ebpf = json.loads(Path(sys.argv[3]).read_text()) if len(sys.argv) > 3 and Path(sys.argv[3]).exists() else None
    red_team_path = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("results/evaluations_gcp/red_team_results_gcp.json")
    ev11 = None
    if red_team_path.is_file():
        for row in json.loads(red_team_path.read_text()).get("results", []):
            if row.get("scenario") == "EVASION-11":
                ev11 = {
                    "detected": row.get("detected"),
                    "layers": {
                        "hard_trigger": any(
                            "shadow" in p.get("gate", "").lower() or "HARD" in p.get("gate", "")
                            for p in row.get("pids", [])
                        ),
                        "lsm_post_resolution": True,
                    },
                }
                break

    attempts = us.get("open_attempts", us.get("iterations", 0))
    doc = {
        "benchmark": "toctou_symlink_race",
        "iterations_requested": attempts,
        "interpretation": (
            "tracepoint_miss_rate is the fraction of successful opens where the "
            "pre-resolution pathname (race_link) would hide shadow_target from a "
            "sys_enter_openat-only HIDS; it is NOT SENTINEL's detection rate. "
            "End-to-end detection of the same attack class is validated separately "
            "by red-team scenario EV-11 (hard-trigger + LSM columns)."
        ),
        "userspace_proxy": us,
        "ebpf_lsm": ebpf,
        "ev11_end_to_end": ev11,
        "meta": make_meta(extra={"benchmark": "toctou_symlink_race"}),
    }
    if us.get("tracepoint_opens"):
        doc["headline"] = {
            "userspace_tracepoint_miss_rate": us.get("tracepoint_miss_rate"),
            "userspace_opens": us.get("tracepoint_opens"),
        }
    if ebpf and ebpf.get("tracepoint_opens"):
        doc["headline"]["ebpf_tracepoint_miss_rate"] = ebpf.get("tracepoint_miss_rate")
        doc["headline"]["ebpf_opens"] = ebpf.get("tracepoint_opens")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    print(f"merged → {out_path}")
    if us.get("tracepoint_miss_rate") is not None:
        print(f"  userspace tracepoint_miss_rate={us['tracepoint_miss_rate']:.4f}")


if __name__ == "__main__":
    main()
