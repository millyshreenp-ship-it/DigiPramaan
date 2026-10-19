"""Abstract LLM Provider interface and audit logging system."""

import abc
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Type, TypeVar
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "audit_trail.log")


def log_audit_trail(
    provider_name: str,
    action: str,
    prompt: str,
    response_raw: str,
    parsed_json: Optional[Dict[str, Any]] = None,
    latency_ms: float = 0.0,
    retry_count: int = 0,
    status: str = "SUCCESS",
    error_message: Optional[str] = None,
) -> None:
    """Appends structured audit record for forensic chain-of-custody and verification (Person 4 consumption)."""
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "provider": provider_name,
        "action": action,
        "latency_ms": round(latency_ms, 2),
        "retry_count": retry_count,
        "status": status,
        "error": error_message,
        "prompt": prompt,
        "response_raw": response_raw,
        "parsed_json": parsed_json,
    }
    log_file = os.getenv("AUDIT_LOG_FILE", AUDIT_LOG_FILE)
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        logging.error(f"Failed to write to audit log: {e}")


class LLMProvider(abc.ABC):
    """Abstract base class for LLM providers."""

    name: str = "base"
    temperature: float = 0.2

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Checks if provider backend is reachable and ready."""
        pass

    @abc.abstractmethod
    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Type[T]] = None,
        action_name: str = "llm_completion",
    ) -> Dict[str, Any]:
        """Generates a structured JSON response with low temperature, validation, and 1 retry."""
        pass
