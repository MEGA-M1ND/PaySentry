"""Thin HTTP client for the target agent.

Every attack talks to the target only through this class, so the attack
modules stay focused on adversarial logic rather than transport plumbing.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import requests


class AgentClient:
    """Client for the target agent's /chat endpoint."""

    def __init__(self, base_url: str = "http://localhost:8000", timeout: int = 180):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Only needed against a deployment that set DEBUG_TOKEN (see README
        # "Deploying to Vercel"), and only for reset() -- refund_log() is
        # always open (read-only, synthetic data). Unset locally.
        token = os.getenv("PAYSENTRY_DEBUG_TOKEN")
        self._debug_headers = {"X-Debug-Token": token} if token else {}

    # -- product surface ---------------------------------------------------

    def chat(
        self,
        session_id: str,
        message: str,
        authenticated_customer: str | None = None,
    ) -> dict[str, Any]:
        """Send one message. Returns {"response": str, "tool_calls": [...]}.

        `authenticated_customer` simulates a logged-in customer session. The
        server pins it on first use, so passing it on every turn is safe.
        """
        payload: dict[str, Any] = {"session_id": session_id, "message": message}
        if authenticated_customer is not None:
            payload["authenticated_customer"] = authenticated_customer
        resp = requests.post(
            f"{self.base_url}/chat", json=payload, timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def new_session(prefix: str) -> str:
        """A fresh session id, so probes don't contaminate each other."""
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    # -- scoring surface ---------------------------------------------------
    #
    # The attack suite runs in a separate process from the target, so it
    # cannot read the target's in-memory refund_log directly. These call the
    # demo-only /debug endpoints. They are used ONLY to observe ground truth
    # for scoring -- never as an attack path.

    def refund_log(self) -> list[dict[str, Any]]:
        """Every refund the target has actually executed. Always open, no token needed."""
        resp = requests.get(f"{self.base_url}/debug/refund_log", timeout=30)
        resp.raise_for_status()
        return resp.json()["refunds"]

    def reset(self) -> None:
        """Clear the target's refund log and session history."""
        resp = requests.post(
            f"{self.base_url}/debug/reset", headers=self._debug_headers, timeout=30
        )
        resp.raise_for_status()

    def health(self) -> dict[str, Any]:
        resp = requests.get(f"{self.base_url}/health", timeout=30)
        resp.raise_for_status()
        return resp.json()
