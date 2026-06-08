"""Rebuild PCABP nginx call-site bloom filter for x86_64 Linux.

Run on GCP VM (or any native Linux host) with .venv activated.
Does not require PyTorch — only ELF parsing (pyelftools + capstone).

Output (override with PCABP_OUT env):
  src/python/sentinel/pcabp/nginx_callsites_x86_64_gcp.pkl
"""
from __future__ import annotations
import os
import sys

NGINX = os.environ.get("PCABP_NGINX", "/usr/sbin/nginx")
OUT   = os.environ.get(
    "PCABP_OUT",
    "src/python/sentinel/pcabp/nginx_callsites_x86_64_gcp.pkl",
)

sys.path.insert(0, "src/python")
# Import call_site_map directly — avoids loading BehavioralEncoder / torch.
from sentinel.pcabp.call_site_map import ValidCallSiteMap  # noqa: E402

if not os.path.exists(NGINX):
    print(f"ERROR: {NGINX} not found", file=sys.stderr)
    sys.exit(1)

print(f"Building PCABP call-site map from {NGINX} ...")
csm = ValidCallSiteMap.build(NGINX)
csm.save(OUT)
size = os.path.getsize(OUT)
print(f"Saved {OUT} ({size} bytes)")

attrs = {a: getattr(csm, a) for a in dir(csm)
         if not a.startswith("_") and not callable(getattr(csm, a))}
print("Public attrs:")
for k, v in attrs.items():
    if isinstance(v, (int, str, float, bool)):
        print(f"  {k}: {v}")
    else:
        print(f"  {k}: <{type(v).__name__}>")

# Smoke test: check a known-bad IP (heap region)
heap_ip = 0x7fffe0000000
in_bloom, delta = csm.check(heap_ip)
print(f"Smoke test — heap IP {heap_ip:#x}: in_bloom={in_bloom}, delta={delta}")
