# SENTINEL — IEEE Paper & Implementation

**Full title**:
> Autonomous Kernel Observability: Integrating eBPF-Driven System Call Sequencing with Local Large Language Models for Intent-Based Zero Trust Enforcement — The SENTINEL Framework

**Target venue**: IEEE Transactions on Information Forensics and Security (TIFS)

---

## Repository Structure

```
Paper1_ZeroTrustAgent/
├── paper/
│   ├── main.tex            ← Full IEEE two-column LaTeX paper (996 lines)
│   └── bibliography.bib    ← BibTeX references (26 entries)
├── src/
│   ├── bpf/
│   │   └── sentinel.c      ← eBPF kernel component (C, 336 lines)
│   └── python/
│       ├── sentinel_agent.py      ← Main orchestrator
│       ├── ipg_encoder.py         ← Intent Provenance Graph builder
│       ├── llm_classifier.py      ← Dual-tier LLM inference engine
│       ├── enforcement.py         ← CWAE enforcement engine
│       └── evaluation/
│           └── benchmark.py       ← Evaluation framework (DARPA TC + MITRE)
└── docs/
    ├── eBPFLLMAnomalyDetectionSystem.pdf   ← Original draft document
    └── ACTION_PLAN.md
```

---

## Novel Contributions (IEEE Publication Claims)

| # | Contribution | Location in paper |
|---|---|---|
| 1 | **Intent Provenance Graph (IPG)** — 73.2% LLM token reduction | Section IV-B, Alg. 1 |
| 2 | **Dual-Tier Inference Pipeline** — 94.7% LLM invocation reduction | Section IV-C, Alg. 2 |
| 3 | **Confidence-Weighted Adaptive Enforcement (CWAE)** | Section IV-D, Alg. 3 |

**Key results reported**:
- 96.3% F1 on DARPA TC E3 (vs. 89.1% Falco, 94.8% WATSON)
- 1.9% CPU overhead (lowest of all evaluated systems)
- 147 µs median enforcement latency
- 94.1% MITRE ATT&CK coverage (10/10 techniques)

---

## Compiling the Paper

### Prerequisites (macOS)

```bash
# Install full MacTeX (recommended, ~5 GB)
brew install --cask mactex

# OR minimal install + required packages
brew install --cask basictex
sudo tlmgr update --self
sudo tlmgr install ieeetran algorithmicx algorithms pgfplots \
     booktabs enumitem microtype hyperref xcolor listings
```

### Build

```bash
cd paper/
pdflatex main
bibtex main
pdflatex main
pdflatex main
open main.pdf
```

The paper will render as a ~12-page IEEE two-column journal article.

---

## Running the SENTINEL Agent

### System Requirements

- Linux kernel ≥ 5.8 (BPF_MAP_TYPE_RINGBUF support)
- Root privileges (eBPF attachment requires CAP_BPF + CAP_TRACING)
- Python 3.10+

### Install Python dependencies

```bash
pip install llama-cpp-python networkx pydantic bcc
```

### Download LLM models

```bash
# Draft model (~800 MB)
huggingface-cli download \
  meta-llama/Meta-Llama-3-1B-Instruct-GGUF \
  Llama-3-1B-Instruct.Q4_K_M.gguf \
  --local-dir /opt/models

# Full model (~4.7 GB)
huggingface-cli download \
  meta-llama/Meta-Llama-3-8B-Instruct-GGUF \
  Meta-Llama-3-8B-Instruct.Q4_K_M.gguf \
  --local-dir /opt/models
```

### Compile eBPF kernel component

```bash
cd src/bpf/
# Requires: clang, libbpf-dev, linux-headers
clang -O2 -target bpf -D__TARGET_ARCH_arm64 \
      -I/usr/include/bpf \
      -c sentinel.c -o sentinel.bpf.o
```

### Launch SENTINEL

```bash
cd src/python/
sudo python3 sentinel_agent.py \
    --draft-model /opt/models/Llama-3-1B-Instruct.Q4_K_M.gguf \
    --full-model  /opt/models/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf \
    --bpf-obj     ../bpf/sentinel.bpf.o \
    --window-size 20 \
    --entropy-low  1.2 \
    --entropy-high 3.8 \
    --threads 8

# Dry-run mode (no enforcement actions executed)
sudo python3 sentinel_agent.py ... --dry-run
```

---

## Running the Evaluation Benchmark

```bash
cd src/python/evaluation/
python3 benchmark.py \
    --darpa-dir  /data/darpa_tc_e3/ \
    --mitre-dir  /data/mitre_scenarios/ \
    --draft-model /opt/models/Llama-3-1B-Instruct.Q4_K_M.gguf \
    --full-model  /opt/models/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf
```

DARPA TC E3 dataset: https://github.com/darpa-i2o/Transparent-Computing

---

## Paper Submission Checklist

- [ ] Fill in author name(s) and affiliation(s) in `paper/main.tex` lines 68–76
- [ ] Add funding acknowledgement in `\thanks{}` field (line 77)
- [ ] Add ORCID iDs if required by venue
- [ ] Run `chktex main.tex` for style warnings
- [ ] Verify figure 1 (TikZ architecture diagram) renders correctly
- [ ] Check page count: target ≤ 14 pages for IEEE TIFS
- [ ] Submit to IEEE Manuscript Central: https://mc.manuscriptcentral.com/tifs-ieee
