"""LLM classifier factory — builds DualTierClassifier from config."""
from __future__ import annotations

from sentinel.config import LLMConfig
from sentinel.llm.base import BaseClassifier, DualTierClassifier
from sentinel.llm.mock import MockClassifier


def make_classifier(config: LLMConfig) -> DualTierClassifier:
    """Return a DualTierClassifier wired to the configured backend."""
    draft: BaseClassifier
    full:  BaseClassifier

    if config.backend == "ollama":
        from sentinel.llm.ollama import OllamaClassifier
        draft = OllamaClassifier(
            base_url=config.ollama_url,
            model=config.draft_model,
            timeout=config.timeout_seconds,
            max_retries=config.max_retries,
            tier="draft",
        )
        full = OllamaClassifier(
            base_url=config.ollama_url,
            model=config.full_model,
            timeout=config.timeout_seconds,
            max_retries=config.max_retries,
            tier="full",
        )
    else:
        draft = MockClassifier(tier="draft")
        full  = MockClassifier(tier="full")

    return DualTierClassifier(
        draft=draft,
        full=full,
        draft_conf_threshold=config.draft_conf_threshold,
    )
