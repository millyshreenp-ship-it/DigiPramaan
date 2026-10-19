"""LLM Provider factory and selector."""

import logging
import os
from typing import Optional

from backend.llm.base import LLMProvider
from backend.llm.mock_provider import MockProvider

logger = logging.getLogger(__name__)


def get_llm_provider(force_provider: Optional[str] = None) -> LLMProvider:
    """Returns the configured LLM provider instance, defaulting safely to MockProvider.
    
    Selection logic:
    1. force_provider argument if supplied
    2. LLM_PROVIDER environment variable ('ollama', 'gemini', 'mock')
    3. If 'ollama' or 'gemini' is requested but unavailable/unconfigured, falls back to MockProvider.
    """
    provider_name = (force_provider or os.getenv("LLM_PROVIDER", "mock")).strip().lower()

    if provider_name == "mock":
        return MockProvider()

    if provider_name == "ollama":
        try:
            from backend.llm.ollama_provider import OllamaProvider
            provider = OllamaProvider()
            if provider.is_available():
                return provider
            logger.warning("Ollama provider selected but host unreachable. Falling back to MockProvider.")
            return MockProvider()
        except ImportError:
            logger.warning("OllamaProvider not yet configured. Falling back to MockProvider.")
            return MockProvider()

    if provider_name == "gemini":
        try:
            from backend.llm.gemini_provider import GeminiProvider
            provider = GeminiProvider()
            if provider.is_available():
                return provider
            logger.warning("Gemini provider selected but unavailable (missing API key?). Falling back to MockProvider.")
            return MockProvider()
        except ImportError:
            logger.warning("GeminiProvider not yet configured. Falling back to MockProvider.")
            return MockProvider()

    logger.info(f"Unrecognized provider '{provider_name}'. Defaulting to MockProvider.")
    return MockProvider()
