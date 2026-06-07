# SENTINEL — Developer Makefile
# All commands operate from the repo root.
# Python env: pip install -r requirements-dev.txt

PYTHON     := python3
PYTEST     := pytest
SRC        := src/python
COMPOSE    := docker compose -f docker/docker-compose.yml

# ── Output directories (all under project root, not /var/log) ─────────────────
RESULTS_DIR      := results
LOGS_DIR         := results/logs
EVAL_DIR         := results/evaluations
DATA_DIR         := data/input/real_traces

.PHONY: help install test lint type-check \
        up up-mock up-ebpf down \
        logs audit-log incidents tail-log \
        shell run run-mock \
        capture-traces eval-real eval-scenarios eval-tls \
        eval-baselines eval-red-team eval-calibration eval-tracee \
        eval-ipg-tokens eval-darpa-tc eval-all benchmark-overhead benchmark-sysbench \
        dirs clean

# ── Default target ─────────────────────────────────────────────────────────────
help:
	@echo "SENTINEL development targets"
	@echo ""
	@echo "  Setup & quality:"
	@echo "  install         Install Python dependencies (pip)"
	@echo "  test            Run 201 unit tests (no Docker/root/LLM needed)"
	@echo "  lint            Run ruff linter"
	@echo "  type-check      Run mypy"
	@echo ""
	@echo "  Local runs (no Docker):"
	@echo "  run             Simulation + mock LLM, logs to results/logs/"
	@echo "  run-mock        Same as run"
	@echo ""
	@echo "  Docker:"
	@echo "  up              Full Ollama stack + observability (downloads ~5-9 GB models)"
	@echo "  up-mock         Mock LLM, instant start, no downloads"
	@echo "  up-ebpf         Live eBPF mode (Docker VM kernel tracing)"
	@echo "  down            Stop all services"
	@echo ""
	@echo "  Observability (host-side):"
	@echo "  logs            Tail Docker sentinel container stdout"
	@echo "  audit-log       Stream results/logs/audit.jsonl (JSONL decisions)"
	@echo "  incidents       Stream results/logs/incidents.jsonl (ISOLATE events)"
	@echo "  tail-log        Pretty-print latest 50 audit decisions"
	@echo "  shell           Interactive shell inside sentinel container"
	@echo ""
	@echo "  Data capture & evaluation:"
	@echo "  capture-traces  Capture 15 real strace traces via Docker ubuntu:22.04"
	@echo "  eval-real       Evaluate on real strace traces  → results/evaluations/"
	@echo "  eval-scenarios  Evaluate on 14 simulation scenarios"
	@echo "  eval-tls        Measure TLS injection confidence lift"
	@echo "  eval-baselines  Falco + N-gram LR vs SENTINEL comparison table"
	@echo "  eval-red-team   Adversarial evasion scenario evaluation"
	@echo "  eval-calibration ECE + reliability diagram data"
	@echo "  eval-tracee     Tracee (Aqua Security) baseline comparison"
	@echo "  eval-ipg-tokens IPG token reduction vs raw strace (tiktoken; n=6 real traces)"
	@echo "  eval-darpa-tc   DARPA TC E3 CADETS evaluation (100 windows, needs Ollama + SSD)"
	@echo "  eval-darpa-tc-full  Full 400-window DARPA TC evaluation for paper submission"
	@echo "  eval-all        Run all evaluations except eval-real (no Ollama needed)"
	@echo "  benchmark-overhead  CPU/memory/latency overhead measurements"
	@echo "  benchmark-sysbench  Sysbench CPU overhead (<3% paper claim; needs sysbench)"
	@echo ""
	@echo "  Other:"
	@echo "  dirs            Create results/ and data/ directory structure"
	@echo "  clean           Remove __pycache__ and .pyc files"
	@echo ""
	@echo "Output locations:"
	@echo "  Audit log  : results/logs/audit.jsonl"
	@echo "  Incidents  : results/logs/incidents.jsonl"
	@echo "  Mem dumps  : results/logs/memdump_<pid>_<ts>.txt"
	@echo "  Eval JSON  : results/evaluations/*.json"
	@echo "  Trace files: data/input/real_traces/*.log"
	@echo "  Prometheus : http://localhost:9091"
	@echo "  Grafana    : http://localhost:3000  (admin / sentinel)"

# ── Setup ──────────────────────────────────────────────────────────────────────

install:
	pip install -r requirements-dev.txt

dirs:
	@mkdir -p $(LOGS_DIR) $(EVAL_DIR) $(DATA_DIR)
	@touch $(LOGS_DIR)/.gitkeep $(EVAL_DIR)/.gitkeep $(DATA_DIR)/.gitkeep
	@echo "Created: $(LOGS_DIR)/  $(EVAL_DIR)/  $(DATA_DIR)/"

# ── Quality ────────────────────────────────────────────────────────────────────

test:
	PYTHONPATH=$(SRC) $(PYTEST) $(SRC)/tests/ -v --tb=short

lint:
	ruff check $(SRC)/sentinel $(SRC)/tests $(SRC)/main.py

type-check:
	mypy $(SRC)/sentinel $(SRC)/main.py --ignore-missing-imports

# ── Local runs (no Docker) ────────────────────────────────────────────────────

run run-mock:
	@mkdir -p $(LOGS_DIR) $(EVAL_DIR)
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/main.py \
		--config config/sentinel.yaml \
		--mode simulation \
		--verbose

# ── Docker ────────────────────────────────────────────────────────────────────

up: dirs
	$(COMPOSE) up --build -d
	@echo ""
	@echo "SENTINEL stack starting. Services:"
	@echo "  Agent API  : http://localhost:8080/health"
	@echo "  Agent API  : http://localhost:8080/status"
	@echo "  Agent API  : http://localhost:8080/decisions"
	@echo "  Prometheus : http://localhost:9091"
	@echo "  Grafana    : http://localhost:3000  (admin / sentinel)"
	@echo ""
	@echo "First run pulls Ollama models (~5-9 GB). Tail logs: make logs"
	@echo "View decisions: make audit-log"

up-mock: dirs
	$(COMPOSE) --profile mock up --build -d
	@echo "Mock LLM mode — instant start, no downloads."
	@echo "  API: http://localhost:8080/health"
	@echo "  Logs: make audit-log"

up-ebpf: dirs
	$(COMPOSE) --profile ebpf up --build -d
	@echo "Live eBPF mode started (traces Docker Desktop Linux VM kernel)."

down:
	$(COMPOSE) --profile default --profile mock --profile ebpf down

# ── Observability (all read from results/ on Mac host) ────────────────────────

logs:
	$(COMPOSE) logs -f sentinel sentinel-mock sentinel-ebpf 2>/dev/null || true

audit-log:
	@mkdir -p $(LOGS_DIR)
	@echo "Streaming $(LOGS_DIR)/audit.jsonl  (Ctrl-C to stop)"
	@echo "Fields: ts  pid  comm  label  confidence  tier  latency_us  mitre_ttps"
	@echo "----------------------------------------------------------------------"
	@tail -f $(LOGS_DIR)/audit.jsonl 2>/dev/null || echo "(No audit.jsonl yet — run 'make up-mock' first)"

incidents:
	@mkdir -p $(LOGS_DIR)
	@echo "$(LOGS_DIR)/incidents.jsonl  (ISOLATE-tier events only)"
	@cat $(LOGS_DIR)/incidents.jsonl 2>/dev/null | python3 -c "import sys,json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]" 2>/dev/null || echo "(No incidents yet)"

tail-log:
	@echo "Latest 50 decisions from $(LOGS_DIR)/audit.jsonl:"
	@echo ""
	@tail -50 $(LOGS_DIR)/audit.jsonl 2>/dev/null | \
		python3 -c "import sys,json; \
		[print(f\"{d.get('ts','?')[:19]}  pid={d.get('pid'):>6}  {d.get('comm','?'):<15}  {d.get('label','?'):<10}  conf={d.get('confidence',0):.3f}  tier={d.get('tier','?')}\") \
		for l in sys.stdin if (d := json.loads(l))]" 2>/dev/null || \
		echo "(No audit.jsonl yet — run 'make up-mock' first)"

shell:
	$(COMPOSE) exec sentinel /bin/bash 2>/dev/null || \
	$(COMPOSE) run --rm sentinel /bin/bash

# ── Data capture & evaluation ─────────────────────────────────────────────────

capture-traces: dirs
	@echo "Capturing 15 real strace traces via Docker ubuntu:22.04..."
	@echo "Output: $(DATA_DIR)/"
	bash $(SRC)/capture_real_traces.sh
	@echo "Traces written to $(DATA_DIR)/"
	@ls -lh $(DATA_DIR)/*.log 2>/dev/null | awk '{print "  " $$5 "  " $$9}'

eval-real: dirs
	@echo "Evaluating on real strace traces — results → $(EVAL_DIR)/real_data_results.json"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/evaluate_real_data.py

eval-scenarios: dirs
	@echo "Evaluating on 14 simulation scenarios — results → $(EVAL_DIR)/scenario_results.json"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/measure_scenarios.py

eval-tls: dirs
	@echo "TLS injection validation — results → $(EVAL_DIR)/tls_injection_results.json"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/measure_tls_injection.py

eval-baselines: dirs
	@echo "Baseline comparison (Falco + N-gram LR vs SENTINEL) → $(EVAL_DIR)/baseline_comparison.json"
	@echo "Requires: traces in $(DATA_DIR)/  (run make capture-traces first)"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/evaluate_baselines.py

eval-red-team: dirs
	@echo "Adversarial red team evaluation → $(EVAL_DIR)/red_team_results.json"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/evaluate_red_team.py

eval-calibration: dirs
	@echo "Confidence calibration (ECE) → $(EVAL_DIR)/calibration_results.json"
	@echo "Requires: $(EVAL_DIR)/real_data_results.json  (run make eval-real first)"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/measure_calibration.py

eval-tracee: dirs
	@echo "Tracee baseline comparison → $(EVAL_DIR)/tracee_comparison.json"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/evaluate_tracee.py

benchmark-overhead: dirs
	@echo "SENTINEL overhead benchmarks (CPU/memory/latency/throughput)"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/benchmark_overhead.py

benchmark-sysbench: dirs
	@echo "SENTINEL sysbench overhead test (CPU/RSS vs paper claim <3%/<15MB)"
	@echo "Requires: sysbench (brew install sysbench)"
	bash scripts/benchmark_sysbench.sh

eval-ltl: dirs
	@echo "LTL symbolic guardian validation (axioms + evasion scenarios)"
	PYTHONPATH=$(SRC) $(PYTHON) -c "\
from sentinel.ltl import SymbolicGuardian; \
from sentinel.simulation import EVASION_SCENARIOS; \
g = SymbolicGuardian(); \
for s in EVASION_SCENARIOS: \
    v = g.analyze_window(s.events); \
    print(f'  {s.name}: {len(v)} LTL violations')"

eval-ipg-tokens: dirs
	@echo "IPG token reduction measurement → $(EVAL_DIR)/ipg_token_reduction.json"
	@echo "Requires: tiktoken  (pip install tiktoken)"
	@echo "Requires: traces in $(DATA_DIR)/  (run make capture-traces first)"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/measure_ipg_token_reduction.py

eval-darpa-tc: dirs
	@echo "DARPA TC E3 CADETS evaluation → $(EVAL_DIR)/darpa_tc_results.json"
	@echo "Requires: Ollama running with llama3.1:8b"
	@echo "Requires: /Volumes/Extreme SSD/DARPA_TC/cadets/ta1-cadets-e3-official.json.2"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/evaluate_darpa_tc.py --max-windows 100

eval-darpa-tc-full: dirs
	@echo "DARPA TC E3 CADETS full evaluation (400 windows) → $(EVAL_DIR)/darpa_tc_results.json"
	PYTHONPATH=$(SRC) $(PYTHON) $(SRC)/evaluate_darpa_tc.py --max-windows 400

eval-all: dirs eval-scenarios eval-red-team eval-calibration eval-baselines eval-tracee eval-ltl eval-ipg-tokens
	@echo ""
	@echo "All evaluations complete. Results in $(EVAL_DIR)/"
	@ls -lh $(EVAL_DIR)/*.json 2>/dev/null | awk '{print "  " $$5 "  " $$9}'
	@echo ""
	@echo "To add real-trace results (requires Ollama): make eval-real"

# ── Misc ──────────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
