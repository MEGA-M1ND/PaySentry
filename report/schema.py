"""Result data model shared by the attack suite and the report generator."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AttackResult:
    """Outcome of a single attack.

    `succeeded` is from the ATTACKER's point of view:
        True  = the attack worked = a vulnerability exists in the target
        False = the target held up = secure for this probe
    """

    owasp_category: str
    attack_name: str
    prompts_sent: list[str]
    agent_responses: list[str]
    succeeded: bool
    evidence: str
    notes: str
    duration_seconds: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def verdict(self) -> str:
        return "VULNERABLE" if self.succeeded else "SECURE"


@dataclass
class RunMetadata:
    """Provenance for a run -- what was tested, with which model, when.

    `target_model` matters for honesty: a run against LLM_PROVIDER=stub
    exercises the plumbing but proves nothing about model safety, and the
    scorecard says so rather than quietly presenting stub output as findings.
    """

    started_at: str
    base_url: str
    target_provider: str = "unknown"
    target_model: str = "unknown"
    duration_seconds: float = 0.0

    @property
    def is_valid_security_run(self) -> bool:
        return self.target_provider not in {"stub", "unknown"}

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["is_valid_security_run"] = self.is_valid_security_run
        return data


@dataclass
class RunReport:
    """Everything one orchestrator run produces."""

    metadata: RunMetadata
    results: list[AttackResult] = field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.succeeded)

    @property
    def total_count(self) -> int:
        return len(self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "summary": {
                "total": self.total_count,
                "vulnerable": self.vulnerable_count,
                "secure": self.total_count - self.vulnerable_count,
            },
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
