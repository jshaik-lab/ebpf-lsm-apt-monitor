# SENTINEL Reproducibility Guide

Primary evaluation platform for IEEE submission: **IONOS VPS Linux XL** (Ubuntu 24.04, 8 vCPU, 16 GB RAM).

| Field | Value |
|-------|--------|
| Provider | IONOS Cloud VPS |
| Plan | VPS 8-16-480 (Linux XL) |
| IP | 74.208.76.97 |
| OS | Ubuntu 24.04 LTS |
| GitHub | https://github.com/jshaik-lab/Paper1_ZeroTrustAgent |
| Ollama models | `llama3.1:8b`, `llama3.2:1b` |

Record after bootstrap: `uname -r`, `uname -m` (insert into paper Section V).

---

## 1. SSH access

See [IONOS_SSH_SETUP.md](IONOS_SSH_SETUP.md). Test:

```bash
ssh sentinel-ionos 'uname -a'
```

---

## 2. One-shot VPS bootstrap

From Mac (after SSH works):

```bash
./scripts/deploy_to_ionos.sh
```

Or manually on the VPS as root:

```bash
curl -fsSL https://raw.githubusercontent.com/jshaik-lab/Paper1_ZeroTrustAgent/main/scripts/bootstrap_ionos.sh | bash -s -- \
  https://github.com/jshaik-lab/Paper1_ZeroTrustAgent.git
```

Expected duration: **20–40 minutes** (Ollama model downloads dominate).

---

## 3. Evaluation commands (on VPS)

```bash
sudo -u sentinel bash -lc '
  cd ~/Paper1_ZeroTrustAgent
  source .venv/bin/activate
  export SENTINEL_EVAL_PLATFORM="IONOS VPS XL Ubuntu 24.04; Ollama llama3.1:8b"

  make test
  make eval-scenarios          # 14 simulation scenarios
  CAPTURE_MODE=native make capture-traces   # ≥50 benign + ≥50 attack (native strace)
  make eval-real
  make eval-calibration
  make benchmark-overhead
'
```

Results: `results/evaluations/*.json`, logs: `results/logs/audit.jsonl`.

---

## 4. DARPA TC E3 CADETS

Copy dataset from Mac (external SSD):

```bash
rsync -avP --progress \
  "/Volumes/Extreme SSD/DARPA_TC/cadets/ta1-cadets-e3-official.json.2" \
  sentinel-ionos:~/Paper1_ZeroTrustAgent/data/darpa/
```

On VPS:

```bash
cd ~/Paper1_ZeroTrustAgent && source .venv/bin/activate

# Behavioral-only (honest comparison to WATSON/UNICORN)
PYTHONPATH=src/python python3 src/python/evaluate_darpa_tc.py \
  --dataset cadets --max-windows 100 \
  --strip-annotations --hard-fraction 0.5 \
  --darpa-path data/darpa/ta1-cadets-e3-official.json.2 \
  --out results/evaluations/darpa_tc_behavioral_v4_linux.json

# TI-aided mode (v8 default — disclose circularity in paper)
PYTHONPATH=src/python python3 src/python/evaluate_darpa_tc.py \
  --dataset cadets --max-windows 100 \
  --darpa-path data/darpa/ta1-cadets-e3-official.json.2 \
  --out results/evaluations/darpa_tc_v8_ti_aided_linux.json

# Full paper run (~hours)
make eval-darpa-tc-full
```

---

## 5. Pull results back to Mac

```bash
scp -r sentinel-ionos:~/Paper1_ZeroTrustAgent/results/evaluations/ \
  ./results/evaluations_linux/
```

---

## 6. Paper build

```bash
cd paper
pdflatex main && bibtex main && pdflatex main && pdflatex main
chktex main.tex
```

---

## 7. Security notes

- Do **not** expose Ollama port 11434 on the public internet.
- Eval-only VPS; no production credentials.
- IONOS blocks outbound SMTP port 25 (irrelevant for this project).

---

## 8. Checklist cross-reference

Track submission readiness in [IEEE_SUBMISSION_CHECKLIST.md](IEEE_SUBMISSION_CHECKLIST.md).
