# Action Plan: Paper 1 (SENTINEL — IEEE TIFS)

**Path:** `/Users/jshaik/projects/EB1A/IEEETechnicalPapers/Paper1_ZeroTrustAgent`  
**Status:** GCP evaluation complete (2026-06-08). Paper synced to measured JSONs.

---

## Completed (2026-06-08)

| Item | Result |
|------|--------|
| GCP full eval chain | 13 `*_gcp.json` + `MANIFEST.json` |
| DARPA hybrid (v5) | F1=0.603, TPR=0.44, FPR=0.02 |
| DARPA LLM-only (v4) | F1=0.597 |
| DARPA TI-aided (v8) | F1=0.915 (circularity caveat) |
| Ablation (5 modes) | Graph-only F1=0.611; hybrid 1/100 LLM calls |
| Real strace (105) | TPR=0.714, FPR=0.291, n=104 |
| IPG compression | 74.0% @ n=20, 92.7% full trace |
| Dual-tier | 35.7% reduction, 12/14 dual vs 14/14 8B |
| LTL FPR | 0/387 benign windows |
| PCABP real nginx | F1=1.0 (controlled classes), 663 x86 sites |
| `paper/main.tex` | Numbers updated from GCP JSONs |
| Documentation | RUNME, REPRO, IEEE checklist, diagrams |

---

## Remaining before IEEE submission

1. **Author metadata** — fill affiliation, funding, dates in `paper/main.tex`
2. **PDF build** — `pdflatex` + `chktex`; verify ≤14 pages
3. **CoVe measurement** — Ollama-backed hallucination rate (not MockClassifier)
4. **High FPR on real traces** — analyze/document benign FP patterns (FPR=0.291)
5. **Baseline honesty** — Falco/N-gram LR contamination fixes
6. **Git release tag** + Zenodo artifact bundle
7. **Optional:** live eBPF demo with non-zero `user_ip` for PCABP end-to-end

---

## Key documents

| Doc | Purpose |
|-----|---------|
| [RUNME.md](RUNME.md) | GCP operations runbook |
| [REPRO.md](REPRO.md) | Reproducibility steps |
| [IEEE_SUBMISSION_CHECKLIST.md](IEEE_SUBMISSION_CHECKLIST.md) | Blocker tracker |
| [sentinel_diagrams.html](sentinel_diagrams.html) | Architecture + measured results |
| [GCP_SETUP_GUIDE.md](GCP_SETUP_GUIDE.md) | VM setup and SSH |

**Deprecated:** IONOS VPS — see [IONOS_SSH_SETUP.md](IONOS_SSH_SETUP.md).
