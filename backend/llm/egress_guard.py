"""Zero-Egress Air-Gap Enforcement Guard.

When ZERO_EGRESS=true or running in local mode (Ollama / Mock), blocks any outbound
network requests to external hosts while permitting loopback/localhost traffic.
Ensures zero data egress for Indian law enforcement forensic workstations.
"""

import logging
import os
import socket
from typing import Any, Tuple

logger = logging.getLogger(__name__)

_GUARD_INSTALLED = False
_ORIGINAL_CONNECT = socket.socket.connect


class AirGapEgressViolationError(PermissionError):
    """Raised when an outbound network call is attempted in air-gapped zero-egress mode."""
    pass


def is_localhost(host: str) -> bool:
    """Checks if destination host is localhost / loopback."""
    host_clean = str(host).strip().lower()
    if host_clean in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if host_clean.startswith("127."):
        return True
    return False


def install_egress_guard() -> None:
    """Installs network interceptor that permits only localhost connections."""
    global _GUARD_INSTALLED
    if _GUARD_INSTALLED:
        return

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        host = ""
        port = 0
        if isinstance(address, tuple) and len(address) >= 2:
            host = address[0]
            port = address[1]
        elif isinstance(address, str):
            host = address

        if not is_localhost(host):
            error_msg = (
                f"[SECURITY AIR-GAP ENFORCEMENT] Outbound network connection blocked: "
                f"attempted egress to '{host}:{port}' while ZERO_EGRESS=true."
            )
            logger.error(error_msg)
            raise AirGapEgressViolationError(error_msg)

        return _ORIGINAL_CONNECT(self, address)

    socket.socket.connect = guarded_connect
    _GUARD_INSTALLED = True
    logger.info("Air-gap egress guard installed. Outbound non-localhost traffic is BLOCKED.")


def remove_egress_guard() -> None:
    """Restores original socket connect behavior (e.g. for testing)."""
    global _GUARD_INSTALLED
    if not _GUARD_INSTALLED:
        return
    socket.socket.connect = _ORIGINAL_CONNECT
    _GUARD_INSTALLED = False
    logger.info("Air-gap egress guard removed.")


def check_and_apply_egress_policy() -> bool:
    """Checks environment configuration and enforces egress policy."""
    zero_egress_env = os.getenv("ZERO_EGRESS", "false").strip().lower()
    provider_env = os.getenv("LLM_PROVIDER", "mock").strip().lower()

    should_guard = zero_egress_env in ("true", "1", "yes") or (
        zero_egress_env != "false" and provider_env in ("mock", "ollama")
    )

    if should_guard:
        install_egress_guard()
        return True
    return False
