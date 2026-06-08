"""Add provenance meta block to an eval result JSON (e.g. tag as *_gcp.json).

Usage: python3 scripts/add_meta_to_json.py <in.json> <out.json>
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0, "src/python")
from sentinel.provenance import make_meta

if len(sys.argv) != 3:
    print("usage: add_meta_to_json.py <in.json> <out.json>", file=sys.stderr)
    sys.exit(2)

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
d = json.loads(src.read_text())
if not isinstance(d, dict):
    d = {"data": d}
d["meta"] = make_meta()
dst.write_text(json.dumps(d, indent=2))
print(f"wrote {dst} ({dst.stat().st_size} bytes)")
# Echo headline numbers for visibility
for k, v in d.items():
    if k == "meta":
        continue
    if isinstance(v, dict) and "p50" in v:
        print(f"  {k}: p50={v['p50']} p99={v.get('p99')}")
    elif isinstance(v, (int, float, str)) and not isinstance(v, bool):
        print(f"  {k}: {v}")
