"""LLM abstraction package."""

from backend.llm.base import LLMProvider, log_audit_trail
from backend.llm.mock_provider import MockProvider
from backend.llm.ollama_provider import OllamaProvider
from backend.llm.gemini_provider import GeminiProvider
from backend.llm.factory import get_llm_provider
from backend.llm.egress_guard import (
    install_egress_guard,
    remove_egress_guard,
    check_and_apply_egress_policy,
    AirGapEgressViolationError,
)

__all__ = [
    "LLMProvider",
    "MockProvider",
    "OllamaProvider",
    "GeminiProvider",
    "get_llm_provider",
    "log_audit_trail",
    "install_egress_guard",
    "remove_egress_guard",
    "check_and_apply_egress_policy",
    "AirGapEgressViolationError",
]
