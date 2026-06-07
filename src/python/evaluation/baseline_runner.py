"""Baseline comparison runner.

Compares SENTINEL against Falco and Tracee by replaying a trace dataset.

NOTE: run_falco() and run_tracee() require the real Falco/Tracee binaries
installed on a native Linux host with the trace dataset present.
They will raise NotImplementedError if called without hardware.
The hardcoded placeholder numbers that were here previously have been removed
because they were fabricated and not reproducible.
"""

import json
import logging
import subprocess
from typing import Dict

logger = logging.getLogger("sentinel.eval.baseline")


class BaselineRunner:
    """
    Evaluates SENTINEL against Falco and Tracee by replaying a trace dataset
    and comparing detection rates, false positives, and latencies.

    Requirements:
      - Falco >= 0.35 installed at /usr/bin/falco (run_falco)
      - Tracee >= 0.20 installed at /usr/bin/tracee (run_tracee)
      - dataset_path points to a replay-able trace directory on a Linux host
      - Root / CAP_BPF capability (eBPF tools require elevated privileges)
    """

    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.results: Dict[str, Dict] = {
            "SENTINEL": {"detected": 0, "false_positives": 0, "latency_ms": 0.0},
            "Falco":    {"detected": None, "false_positives": None, "latency_ms": None},
            "Tracee":   {"detected": None, "false_positives": None, "latency_ms": None},
        }

    def run_falco(self) -> None:
        """
        Run Falco on the dataset and collect TP/FP/latency.

        Requires: real Falco binary + native Linux host.
        Raises NotImplementedError on non-Linux or if falco binary is absent.
        """
        raise NotImplementedError(
            "run_falco() requires the real Falco binary on a native Linux host. "
            "Install Falco >= 0.35 via https://falco.org and run on Linux with "
            "root privileges. No fabricated numbers are used here."
        )

    def run_tracee(self) -> None:
        """
        Run Tracee on the dataset and collect TP/FP/latency.

        Requires: real Tracee binary + native Linux host.
        Raises NotImplementedError on non-Linux or if tracee binary is absent.
        """
        raise NotImplementedError(
            "run_tracee() requires the real Tracee binary on a native Linux host. "
            "Install Tracee >= 0.20 via https://aquasecurity.github.io/tracee and "
            "run on Linux with CAP_BPF. No fabricated numbers are used here."
        )

    def run_sentinel(self, tp: int, fp: int, latency_ms: float) -> None:
        """Record SENTINEL results (passed in from actual evaluation run)."""
        self.results["SENTINEL"]["detected"] = tp
        self.results["SENTINEL"]["false_positives"] = fp
        self.results["SENTINEL"]["latency_ms"] = latency_ms

    def generate_report(self) -> str:
        report = json.dumps(self.results, indent=2)
        logger.info("Baseline Comparison Report:\n%s", report)
        return report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    runner = BaselineRunner("/data/darpa_tc_e3")
    # SENTINEL results from results/evaluations/real_data_results.json
    # TPR=1.0 (8/8 attack), FPR=0.286 (2/7 benign FP), n=15
    runner.run_sentinel(tp=8, fp=2, latency_ms=4200.0)
    # Falco / Tracee require real hardware — see class docstring
    print(runner.generate_report())
