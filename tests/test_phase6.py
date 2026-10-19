"""Phase 6 Unit Tests: LLM Providers (Ollama, Gemini, Mock), ZERO_EGRESS air-gap guard, and Demo Seed."""

import os
import socket
import pytest

from backend.llm.base import LLMProvider
from backend.llm.mock_provider import MockProvider
from backend.llm.ollama_provider import OllamaProvider
from backend.llm.gemini_provider import GeminiProvider
from backend.llm.factory import get_llm_provider
from backend.llm.egress_guard import (
    install_egress_guard,
    remove_egress_guard,
    AirGapEgressViolationError,
    is_localhost,
)
from scripts.seed_demo import seed


def test_ollama_provider_graceful_fallback():
    """Verifies OllamaProvider gracefully falls back to MockProvider when host is unreachable."""
    # Point to non-existent local port
    provider = OllamaProvider(host="http://localhost:59999", timeout_sec=0.5)
    assert provider.is_available() is False

    # Should not crash; must fall back to MockProvider
    result = provider.generate_json(
        prompt="Summarize events EVT-0040, EVT-0043 for usb theft",
        action_name="test_ollama_fallback",
    )
    assert isinstance(result, dict)
    assert "summary" in result
    assert len(result["summary"]) > 0


def test_gemini_provider_missing_key_fallback():
    """Verifies GeminiProvider gracefully falls back to MockProvider when GEMINI_API_KEY is not set."""
    provider = GeminiProvider(api_key="")
    assert provider.is_available() is False

    result = provider.generate_json(
        prompt="Summarize events EVT-0040, EVT-0043",
        action_name="test_gemini_fallback",
    )
    assert isinstance(result, dict)
    assert "summary" in result


def test_provider_factory_selection():
    """Verifies factory resolves providers with fallback."""
    p_mock = get_llm_provider("mock")
    assert isinstance(p_mock, MockProvider)

    # When ollama is not running, falls back safely to MockProvider
    p_ollama = get_llm_provider("ollama")
    assert isinstance(p_ollama, (OllamaProvider, MockProvider))


def test_zero_egress_air_gap_enforcement():
    """Verifies that ZERO_EGRESS prevents any network socket connection to external hosts."""
    assert is_localhost("localhost") is True
    assert is_localhost("127.0.0.1") is True
    assert is_localhost("8.8.8.8") is False
    assert is_localhost("api.openai.com") is False

    try:
        install_egress_guard()

        # External connection must be blocked with AirGapEgressViolationError
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(AirGapEgressViolationError) as exc_info:
            s.connect(("8.8.8.8", 53))

        assert "SECURITY AIR-GAP ENFORCEMENT" in str(exc_info.value)
        s.close()

    finally:
        remove_egress_guard()


def test_seed_demo_script():
    """Verifies that the seed demo script runs without error and validates sample files."""
    seed()
