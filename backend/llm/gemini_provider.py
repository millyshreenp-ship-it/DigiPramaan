"""Gemini LLM Provider (Optional cloud provider via GEMINI_API_KEY)."""

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


class GeminiProvider(LLMProvider):
    name: str = "gemini"
    temperature: float = 0.2

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self._fallback_provider = MockProvider()

    def is_available(self) -> bool:
        """Returns True if API key is present."""
        return bool(self.api_key and len(self.api_key.strip()) > 5)

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Type[T]] = None,
        action_name: str = "gemini_completion",
    ) -> Dict[str, Any]:
        """Calls Gemini API with low temperature and JSON response schema, with fallback."""
        if not self.is_available():
            logger.warning("GEMINI_API_KEY not set. Falling back to MockProvider.")
            return self._fallback_provider.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                schema=schema,
                action_name=f"{action_name}_fallback_nokey",
            )

        start_time = time.perf_counter()
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

        sys_instruction = system_prompt or (
            "You are a Digital Forensics Examiner for Indian Law Enforcement. "
            "Output strictly valid JSON with exact event citations. Adhere to Indian forensic standards."
        )

        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "systemInstruction": {
                "parts": [{"text": sys_instruction}]
            },
            "generationConfig": {
                "temperature": self.temperature,
                "responseMimeType": "application/json",
            },
        }

        last_error = None
        for attempt in range(2):
            try:
                resp = requests.post(url, json=payload, timeout=25.0)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        raw_text = candidates[0]["content"]["parts"][0]["text"]
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
                    last_error = f"Gemini HTTP {resp.status_code}: {resp.text}"
            except Exception as e:
                last_error = str(e)
                time.sleep(0.5)

        logger.warning(
            f"Gemini API call failed ({last_error}). Falling back to deterministic MockProvider."
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
        """Extracts JSON object from text."""
        text_clean = text.strip()
        if text_clean.startswith("```"):
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text_clean)
            if match:
                text_clean = match.group(1).strip()
        return json.loads(text_clean)
