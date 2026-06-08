"""Generate results/evaluations_gcp/MANIFEST.json — a reproducibility manifest
that summarises every cited paper-grade JSON: SHA-256, byte size, meta block,
and headline metrics. Designed for reviewer audit and Zenodo artifact bundling.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

RESULTS_DIR = Path(__file__).parent.parent / "results" / "evaluations_gcp"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def summarise(path: Path) -> dict:
    info: dict = {
        "file":      path.name,
        "bytes":     path.stat().st_size,
        "sha256":    sha256(path),
        "modified":  datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
    }
    if path.suffix == ".json":
        try:
            d = json.loads(path.read_text())
            info["meta"] = d.get("meta", "MISSING")
            # Pull a small selection of headline metrics
            headline = {}
            for k in ("f1", "tpr", "fpr", "precision", "accuracy",
                      "fpr_ci_95", "n_windows", "n_traces"):
                if isinstance(d, dict) and k in d:
                    headline[k] = d[k]
            for k in ("ipg_ms", "cwae_ms", "memory", "detector_throughput"):
                if isinstance(d, dict) and k in d and isinstance(d[k], dict):
                    if "p50" in d[k]:
                        headline[k] = {
                            "p50": d[k]["p50"],
                            "p99": d[k].get("p99"),
                        }
                    else:
                        headline[k] = d[k]
            if isinstance(d, dict) and "recommended_claim" in d:
                headline["recommended_claim"] = d["recommended_claim"]
            if headline:
                info["headline"] = headline
        except json.JSONDecodeError:
            info["error"] = "invalid JSON"
    return info


def main() -> int:
    if not RESULTS_DIR.exists():
        print(f"no such dir: {RESULTS_DIR}", file=sys.stderr)
        return 1

    entries = []
    for f in sorted(RESULTS_DIR.iterdir()):
        if f.name in {"MANIFEST.json", ".DS_Store"} or not f.is_file():
            continue
        entries.append(summarise(f))

    manifest = {
        "schema":    "sentinel-results-manifest-v1",
        "generated": datetime.now(timezone.utc).isoformat(),
        "entries":   entries,
        "integrity_rules": [
            "Every entry tagged for paper citation must have meta.ollama_fallback_to_mock_count == 0",
            "Every entry must have meta.system != 'Darwin' (GCP VM only)",
            "Every entry must have meta.backend == 'ollama' OR be a non-LLM measurement",
            "meta.machine must equal 'x86_64' for VPS-platform attestation",
            "git_sha should match a tagged submission commit",
        ],
    }

    out = RESULTS_DIR / "MANIFEST.json"
    out.write_text(json.dumps(manifest, indent=2))
    print(f"wrote {out}  ({out.stat().st_size} bytes, {len(entries)} entries)")
    print("\nSummary of integrity flags:")
    for e in entries:
        meta = e.get("meta", {})
        if not isinstance(meta, dict):
            print(f"  ⚠ {e['file']}: NO META BLOCK")
            continue
        flags = []
        if meta.get("backend") not in ("ollama", "unknown", None):
            flags.append(f"backend={meta['backend']}")
        elif meta.get("backend") == "unknown":
            flags.append("backend=unknown (non-LLM eval?)")
        if meta.get("system") == "Darwin":
            flags.append("MAC_HOST_REJECT")
        if meta.get("platform") and "MacBook" in str(meta.get("platform")):
            flags.append("MAC_PLATFORM_REJECT")
        if meta.get("ollama_fallback_to_mock_count", 0) > 0:
            flags.append(f"MOCK_FALLBACKS={meta['ollama_fallback_to_mock_count']}")
        if meta.get("machine") and meta["machine"] != "x86_64":
            flags.append(f"machine={meta['machine']}")
        status = "✅" if not any("MOCK" in f for f in flags) else "🔴"
        print(f"  {status} {e['file']}: {', '.join(flags) if flags else 'clean'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
