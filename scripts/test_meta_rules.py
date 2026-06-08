"""Test deterministic meta-rules on DARPA TC E3 CADETS windows to see their performance."""
import sys
import os
import json
import logging
from collections import defaultdict
from pathlib import Path

# Add src/python to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "python"))

from evaluate_darpa_tc import build_labeled_windows, CDM18Parser, CADETS_ATTACK_WINDOWS
from sentinel.ipg import IPGBuilder, _is_external_routable, _KNOWN_DAEMONS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_meta_rules")

def main():
    darpa_path = Path("data/darpa/ta1-cadets-e3-official.json.2")
    if not darpa_path.exists():
        logger.error(f"Dataset not found at {darpa_path}")
        sys.exit(1)

    print(f"Loading windows from {darpa_path}...")
    parser = CDM18Parser()
    windows = build_labeled_windows(
        parser.stream(darpa_path),
        attack_windows=CADETS_ATTACK_WINDOWS,
        window_size=20,
        max_attack=200,
        max_benign=200,
        hard_fraction=0.5
    )

    print(f"Loaded {len(windows)} windows.")
    ipg_builder = IPGBuilder()

    # We want to test different rule combinations:
    # Rule 1: outbound_ext > 0 AND exec_after_net
    # Rule 2: (outbound_ext > 0 AND exec_after_net) OR unusual_comm
    # Rule 3: outbound_ext > 0
    # Rule 4: exec_after_net
    # Rule 5: unusual_comm

    stats = defaultdict(lambda: defaultdict(int))

    for idx, w in enumerate(windows):
        G = ipg_builder.build(w.events)
        
        # Calculate features manually to verify
        outbound_ext = 0
        net_con_seen = False
        exec_after_net = False
        for _, _, data in G.edges(data=True):
            sc  = data.get("sc_label", "")
            res = data.get("resource", "")
            if sc == "connect":
                net_con_seen = True
                if _is_external_routable(res):
                    outbound_ext += 1
            elif sc == "execve" and net_con_seen:
                exec_after_net = True
        
        unusual_comm = any(
            n.comm.lower() not in _KNOWN_DAEMONS for n in G.nodes()
        )

        label = "ATTACK_" + (w.gt_name or "unknown") if w.is_attack else "BENIGN"

        stats[label]["total"] += 1
        if outbound_ext > 0:
            stats[label]["outbound_ext > 0"] += 1
        if exec_after_net:
            stats[label]["exec_after_net"] += 1
        if unusual_comm:
            stats[label]["unusual_comm"] += 1
        if outbound_ext > 0 and exec_after_net:
            stats[label]["outbound_ext > 0 AND exec_after_net"] += 1
        if (outbound_ext > 0 and exec_after_net) or unusual_comm:
            stats[label]["(outbound_ext > 0 AND exec_after_net) OR unusual_comm"] += 1

    print("\n=== RULE EVALUATION MATRIX ===")
    print(f"{'Label':<30} | {'Total':<6} | {'OutExt>0':<8} | {'ExecAfterNet':<12} | {'UnusualComm':<11} | {'OutExt&Exec':<11} | {'(OutExt&Exec)|Unusual':<20}")
    print("-" * 115)
    for label, counts in sorted(stats.items()):
        print(f"{label:<30} | "
              f"{counts['total']:<6} | "
              f"{counts['outbound_ext > 0']:<8} | "
              f"{counts['exec_after_net']:<12} | "
              f"{counts['unusual_comm']:<11} | "
              f"{counts['outbound_ext > 0 AND exec_after_net']:<11} | "
              f"{counts['(outbound_ext > 0 AND exec_after_net) OR unusual_comm']:<20}")

if __name__ == "__main__":
    main()
