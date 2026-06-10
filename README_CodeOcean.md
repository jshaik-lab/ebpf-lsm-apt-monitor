# SENTINEL — Code Ocean Capsule

**Paper:** SENTINEL: LSM-eBPF Co-Design with Graph-Structured LLM Inference for Zero-Trust APT Detection  
**Submitted to:** IEEE Transactions on Information Forensics and Security (T-IFS-27486-2026)  
**GitHub:** https://github.com/jshaik-lab/ebpf-lsm-apt-monitor  
**Author:** Juharasha Shaik, Independent Researcher

---

## Quick Start (no kernel or LLM required)

```bash
pip install -r requirements.txt
python run.py
```

This runs the full unit test suite (218 tests) and a simulation-mode demo using a mock LLM classifier — no Ollama, no root, no eBPF kernel needed.

---

## What This Code Does

SENTINEL is a host-based intrusion detection system that combines:
- **eBPF LSM hooks** for kernel-level syscall telemetry (Linux >= 5.7)
- **Intent Provenance Graph (IPG)** for compact behavioral fingerprinting
- **Dual-tier LLM inference** (llama3.2:1b draft + llama3.1:8b full)
- **LTL Symbolic Guardian** for formal safety enforcement
- **PCABP** for process-injection detection via call-site analysis

---

## Reproducing Paper Results

Full evaluation requires:
- Linux kernel >= 5.7 with `CONFIG_BPF_LSM=y`
- [Ollama](https://ollama.ai) with `llama3.1:8b` and `llama3.2:1b` pulled
- GCP g2-standard-4 (NVIDIA L4) recommended for paper-grade numbers

```bash
# Install dependencies
pip install -r requirements.txt

# Run unit tests
make test

# 14 MITRE ATT&CK scenarios (requires Ollama)
make eval-scenarios

# Real strace evaluation (requires Ollama)
make eval-real

# DARPA TC E3 CADETS evaluation (requires dataset + Ollama)
make eval-darpa-tc
```

GCP evaluation results are in `results/evaluations_gcp/`.

---

## Key Source Files

| File | Description |
|------|-------------|
| `src/python/sentinel/ipg.py` | Intent Provenance Graph (Algorithm 1) |
| `src/python/sentinel/llm/base.py` | Dual-Tier Inference Pipeline (Algorithm 2) |
| `src/python/sentinel/enforcement.py` | CWAE Engine (Algorithm 3) |
| `src/python/sentinel/ltl.py` | LTL Symbolic Guardian |
| `src/python/sentinel/cove.py` | Chain of Verification (CoVe) |
| `src/python/sentinel/pcabp/` | PCABP call-site analysis module |
| `src/python/evaluate_darpa_tc.py` | DARPA TC E3 CADETS evaluation script |

---

## Note on Reproducibility

The eBPF kernel tracing layer requires a Linux host with BPF LSM enabled.
The Code Ocean capsule runs the simulation and test layers only.
All paper-reported numbers were produced on GCP (g2-standard-4, NVIDIA L4,
kernel 6.17.0-1018-gcp) and are archived in `results/evaluations_gcp/`.
