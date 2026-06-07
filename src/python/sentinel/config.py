"""SENTINEL configuration — Pydantic models loaded from YAML with env-var overrides."""
from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field


class EntropyConfig(BaseModel):
    window_size:    int   = 64
    low_threshold:  float = 1.2
    high_threshold: float = 3.8


class ProcessingConfig(BaseModel):
    syscall_window_size: int           = 20
    entropy:             EntropyConfig = Field(default_factory=EntropyConfig)
    max_concurrent_llm:  int           = 4   # asyncio.Semaphore limit


class LLMConfig(BaseModel):
    backend:              Literal["ollama", "mock"] = "ollama"
    ollama_url:           str   = "http://localhost:11434"
    draft_model:          str   = "llama3.2:3b"
    full_model:           str   = "llama3.1:8b"
    draft_conf_threshold: float = 0.90
    timeout_seconds:      int   = 30
    max_retries:          int   = 3


class EnforcementConfig(BaseModel):
    dry_run:      bool = True
    audit_log:    str  = "/var/log/sentinel/audit.jsonl"
    incident_log: str  = "/var/log/sentinel/incidents.jsonl"


class APIConfig(BaseModel):
    host:    str  = "0.0.0.0"
    port:    int  = 8080
    enabled: bool = True


class MetricsConfig(BaseModel):
    enabled: bool = True
    port:    int  = 9090


class BPFConfig(BaseModel):
    obj_path:         str = "src/bpf/sentinel.bpf.o"
    poll_interval_ms: int = 50


class SimulationConfig(BaseModel):
    pause_seconds: float = 2.0
    attack_rate:   float = 0.3   # fraction of scenarios that are attacks
    repeat:        bool  = True
    jitter_ms:     int   = 100   # max random delay between events (ms)


class EGTEConfig(BaseModel):
    """Evidence-Gated Tier-Calibrated Enforcement configuration.

    Disabled by default (enabled=false) so existing CWAE behavior is unchanged.

    Fields
    ------
    enabled          : activate EGTE layer in AuditorAgent pipeline.
    alpha            : split-conformal miscoverage level ∈ (0, 1).
                       Controls P(benign window gets uncapped tier) ≤ alpha.
    calibration_path : optional path to JSONL of EscalationSample records.
                       If omitted or missing, calibrator starts unfitted and
                       fails closed (all windows capped to LOG_ONLY).
    cove_hal_threshold: hallucination_rate above which CoVe caps to LOG_ONLY.
    """
    enabled:            bool            = False
    alpha:              float           = 0.10
    calibration_path:   Optional[str]   = None
    cove_hal_threshold: float           = 0.50


class SentinelConfig(BaseModel):
    mode:       Literal["simulation", "live"] = "simulation"
    log_level:  str                           = "INFO"
    log_format: Literal["json", "text"]       = "json"

    llm:         LLMConfig         = Field(default_factory=LLMConfig)
    processing:  ProcessingConfig  = Field(default_factory=ProcessingConfig)
    enforcement: EnforcementConfig = Field(default_factory=EnforcementConfig)
    api:         APIConfig         = Field(default_factory=APIConfig)
    metrics:     MetricsConfig     = Field(default_factory=MetricsConfig)
    bpf:         BPFConfig         = Field(default_factory=BPFConfig)
    simulation:  SimulationConfig  = Field(default_factory=SimulationConfig)
    egte:        EGTEConfig        = Field(default_factory=EGTEConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "SentinelConfig":
        text = Path(path).read_text()
        data = yaml.safe_load(text) or {}
        return cls.model_validate(data)

    @classmethod
    def defaults(cls) -> "SentinelConfig":
        return cls()
