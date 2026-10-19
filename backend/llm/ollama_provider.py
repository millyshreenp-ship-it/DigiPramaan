"""Ollama LLM Provider for Local Air-Gapped Forensic Reasoning."""

import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional, Type, TypeVar
import requests
from pydantic import BaseModel

from backend.llm.base import LLMProvider, log_audit_trail
from backend.llm.mock_provider import MockProvider

T = TypeVar("T", bound=BaseModel)
logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    name: str = "ollama"
    temperature: float = 0.2

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        timeout_sec: float = 30.0,
    ):
        self.host = (host or os.getenv("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
        self.timeout_sec = timeout_sec
        self._fallback_provider = MockProvider()

    def is_available(self) -> bool:
        """Pings local Ollama service with low timeout."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=1.5)
            return resp.status_code == 200
        except Exception:
            return False

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Type[T]] = None,
        action_name: str = "ollama_completion",
    ) -> Dict[str, Any]:
        """Calls local Ollama instance with temperature=0.2 and JSON mode, with 1 retry and fallback."""
        start_time = time.perf_counter()
        sys_msg = system_prompt or (
            "You are a Digital Forensics Examiner for Indian Law Enforcement. "
            "Output strictly valid JSON with exact citations to event IDs. Do not output markdown text."
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": sys_msg,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "top_p": 0.9,
            },
        }

        last_error = None
        for attempt in range(2):
            try:
                resp = requests.post(
                    f"{self.host}/api/generate",
                    json=payload,
                    timeout=self.timeout_sec,
                )
                if resp.status_code == 200:
                    raw_text = resp.json().get("response", "")
                    parsed = self._extract_json(raw_text)

                    if schema:
                        validated = schema.model_validate(parsed)
                        final_data = validated.model_dump()
                    else:
                        final_data = parsed

                    latency_ms = (time.perf_counter() - start_time) * 1000
                    log_audit_trail(
                        provider_name=self.name,
                        action=action_name,
                        prompt=prompt,
                        response_raw=raw_text,
                        parsed_json=final_data,
                        latency_ms=latency_ms,
                        retry_count=attempt,
                        status="SUCCESS",
                    )
                    return final_data
                else:
                    last_error = f"Ollama HTTP {resp.status_code}: {resp.text}"
            except Exception as e:
                last_error = str(e)
                time.sleep(0.5)

        logger.warning(
            f"Ollama call failed ({last_error}). Executing graceful fallback to deterministic MockProvider."
        )
        latency_ms = (time.perf_counter() - start_time) * 1000
        log_audit_trail(
            provider_name=self.name,
            action=action_name,
            prompt=prompt,
            response_raw="[FALLBACK TO MOCK]",
            parsed_json=None,
            latency_ms=latency_ms,
            retry_count=1,
            status="FALLBACK_TRIGGERED",
            error_message=last_error,
        )
        return self._fallback_provider.generate_json(
            prompt=prompt,
            system_prompt=system_prompt,
            schema=schema,
            action_name=f"{action_name}_fallback",
        )

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extracts JSON object from output even if enclosed in markdown code fences."""
        text_clean = text.strip()
        if text_clean.startswith("```"):
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text_clean)
            if match:
                text_clean = match.group(1).strip()
        return json.loads(text_clean)
