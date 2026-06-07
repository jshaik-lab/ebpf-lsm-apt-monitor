"""Prometheus metrics registry — module-level singletons."""
from prometheus_client import Counter, Gauge, Histogram, start_http_server

events_total = Counter(
    "sentinel_events_total",
    "Total kernel events processed",
)
llm_calls_total = Counter(
    "sentinel_llm_calls_total",
    "LLM inference calls by model tier",
    ["tier"],          # draft | full | mock
)
enforcement_total = Counter(
    "sentinel_enforcement_total",
    "Enforcement actions taken by tier",
    ["action"],        # LOG_ONLY | PAUSE | KILL | QUARANTINE | ISOLATE
)
threats_total = Counter(
    "sentinel_threats_detected_total",
    "Threat detections labelled by MITRE TTP",
    ["ttp"],
)
llm_latency_seconds = Histogram(
    "sentinel_llm_latency_seconds",
    "LLM inference latency in seconds",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)
enforcement_latency_seconds = Histogram(
    "sentinel_enforcement_latency_seconds",
    "Enforcement decision latency in seconds",
    buckets=[1e-5, 1e-4, 5e-4, 1e-3, 5e-3, 1e-2, 5e-2, 0.1],
)
active_pids = Gauge(
    "sentinel_active_pids",
    "Number of PIDs currently tracked in sliding windows",
)
queue_depth = Gauge(
    "sentinel_event_queue_depth",
    "Current async event queue depth",
)
llm_reduction_ratio = Gauge(
    "sentinel_llm_invocation_reduction_ratio",
    "Fraction of windows resolved by draft model without full-model escalation",
)


def start_metrics_server(port: int) -> None:
    start_http_server(port)
