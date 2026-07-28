"""Session/ledger storage, backed by whatever process model is actually running.

Local dev (`python target_agent/run_agent.py`) is one long-lived process, so
plain in-memory dicts work fine and that's the default -- zero setup, matches
every stage of this project up to now.

Deployed on Vercel, the FastAPI app runs as a serverless function. Instances
are ephemeral and requests are not guaranteed to land on the same one, so a
module-level dict would silently lose conversation history and -- worse --
the refund_log ground truth this entire project scores against. When Vercel
has a KV store attached, it injects KV_REST_API_URL / KV_REST_API_TOKEN; this
module switches to that automatically. There is no separate flag to keep in
sync with the environment -- the presence of those two variables IS the
switch, so local dev and the deployed build run identical code.

KV is Vercel's rebrand of Upstash Redis, and Upstash publishes a REST-based
Python client (`upstash-redis`) built exactly for this: no persistent TCP
connection, which is what makes it viable inside a serverless function.
"""

from __future__ import annotations

import json
import os
from typing import Any

from langchain_core.messages import BaseMessage, messages_from_dict, messages_to_dict

_KV_URL = os.getenv("KV_REST_API_URL")
_KV_TOKEN = os.getenv("KV_REST_API_TOKEN")
USING_KV = bool(_KV_URL and _KV_TOKEN)

_REFUND_LOG_KEY = "paysentry:refund_log"


class _MemoryBackend:
    """Default backend: the same in-memory dicts this project always used."""

    def __init__(self) -> None:
        self.sessions: dict[str, list[BaseMessage]] = {}
        self.identities: dict[str, str] = {}
        self.refunds: list[dict[str, Any]] = []

    def get_history(self, session_id: str) -> list[BaseMessage]:
        return list(self.sessions.get(session_id, []))

    def set_history(self, session_id: str, messages: list[BaseMessage]) -> None:
        self.sessions[session_id] = list(messages)

    def get_identity(self, session_id: str) -> str | None:
        return self.identities.get(session_id)

    def pin_identity(self, session_id: str, identity: str) -> str:
        """Set identity only if this session has none yet; return the pinned value."""
        return self.identities.setdefault(session_id, identity)

    def append_refund(self, record: dict[str, Any]) -> None:
        self.refunds.append(record)

    def list_refunds(self) -> list[dict[str, Any]]:
        return list(self.refunds)

    def session_count(self) -> int:
        return len(self.sessions)

    def reset(self) -> None:
        self.sessions.clear()
        self.identities.clear()
        self.refunds.clear()


class _KVBackend:
    """Vercel KV (Upstash Redis REST API) backend for serverless deployment."""

    def __init__(self, url: str, token: str) -> None:
        from upstash_redis import Redis  # imported lazily -- see module docstring

        self._redis = Redis(url=url, token=token)

    @staticmethod
    def _history_key(session_id: str) -> str:
        return f"paysentry:history:{session_id}"

    @staticmethod
    def _identity_key(session_id: str) -> str:
        return f"paysentry:identity:{session_id}"

    def get_history(self, session_id: str) -> list[BaseMessage]:
        raw = self._redis.get(self._history_key(session_id))
        if not raw:
            return []
        return messages_from_dict(json.loads(raw))

    def set_history(self, session_id: str, messages: list[BaseMessage]) -> None:
        self._redis.set(self._history_key(session_id), json.dumps(messages_to_dict(messages)))

    def get_identity(self, session_id: str) -> str | None:
        return self._redis.get(self._identity_key(session_id))

    def pin_identity(self, session_id: str, identity: str) -> str:
        # SETNX/NX: only takes effect if nothing is stored yet, matching the
        # in-memory backend's setdefault semantics -- a session's identity
        # cannot be changed once set, by an attacker or otherwise.
        self._redis.set(self._identity_key(session_id), identity, nx=True)
        return self._redis.get(self._identity_key(session_id))

    def append_refund(self, record: dict[str, Any]) -> None:
        self._redis.rpush(_REFUND_LOG_KEY, json.dumps(record))

    def list_refunds(self) -> list[dict[str, Any]]:
        raw_list = self._redis.lrange(_REFUND_LOG_KEY, 0, -1)
        return [json.loads(r) for r in raw_list]

    def session_count(self) -> int:
        # Approximate: KV has no cheap "count sessions" primitive without
        # maintaining a separate index, and nothing here depends on the exact
        # number -- /health reports it purely as an eyeballed liveness signal.
        return len(self._redis.keys("paysentry:history:*"))

    def reset(self) -> None:
        keys = self._redis.keys("paysentry:history:*") + self._redis.keys("paysentry:identity:*")
        if keys:
            self._redis.delete(*keys)
        self._redis.delete(_REFUND_LOG_KEY)


_backend = _KVBackend(_KV_URL, _KV_TOKEN) if USING_KV else _MemoryBackend()


def get_history(session_id: str) -> list[BaseMessage]:
    return _backend.get_history(session_id)


def set_history(session_id: str, messages: list[BaseMessage]) -> None:
    _backend.set_history(session_id, messages)


def get_identity(session_id: str) -> str | None:
    return _backend.get_identity(session_id)


def pin_identity(session_id: str, identity: str) -> str:
    return _backend.pin_identity(session_id, identity)


def append_refund(record: dict[str, Any]) -> None:
    _backend.append_refund(record)


def list_refunds() -> list[dict[str, Any]]:
    return _backend.list_refunds()


def session_count() -> int:
    return _backend.session_count()


def reset() -> None:
    _backend.reset()
