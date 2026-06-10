"""
SENTINEL — Code Ocean entry point.

Runs the unit test suite in simulation mode (no kernel, no LLM required).
Full execution requires Linux kernel >= 5.7 with CONFIG_BPF_LSM=y and
Ollama running locally with llama3.1:8b and llama3.2:1b pulled.

See README_CodeOcean.md for full setup instructions.
"""
import subprocess
import sys
import os

os.environ.setdefault("PYTHONPATH", "src/python")
sys.path.insert(0, "src/python")

print("=" * 60)
print("SENTINEL — Simulation Mode + Unit Tests")
print("=" * 60)

RESULTS_DIR = "/results" if os.path.isdir("/results") else "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

print("\n[1/2] Running unit tests (no LLM/kernel needed)...")
junit_xml = os.path.join(RESULTS_DIR, "test_results.xml")
result = subprocess.run(
    [sys.executable, "-m", "pytest", "src/python/tests/", "-v", "--tb=short",
     f"--junitxml={junit_xml}"],
    env={**os.environ, "PYTHONPATH": "src/python"},
)

print("\n[2/2] Running simulation mode (mock LLM)...")
sim_out = os.path.join(RESULTS_DIR, "simulation_output.log")
with open(sim_out, "w") as f:
    subprocess.run(
        [sys.executable, "src/python/main.py",
         "--mode", "simulation",
         "--llm-backend", "mock",
         "--max-events", "50"],
        env={**os.environ,
             "PYTHONPATH": "src/python",
             "SENTINEL__MODE": "simulation",
             "SENTINEL__LLM__BACKEND": "mock"},
        stdout=f, stderr=subprocess.STDOUT,
    )

print(f"\nDone. Results saved to {RESULTS_DIR}/")
sys.exit(result.returncode)
