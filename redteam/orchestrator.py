"""Run the full attack suite against a target agent and record the results.

Usage:
    python redteam/orchestrator.py [BASE_URL]

Writes reports/attack_results.json and prints a live table as each attack
finishes. Exit code is 0 when the run completes -- finding vulnerabilities is
a successful run, not a failure. CI gating is Stage 7's job (promptfoo), which
asserts on specific behaviours rather than on the count of findings.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

# Allow `python redteam/orchestrator.py` from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redteam.attacks import (  # noqa: E402
    excessive_agency,
    info_disclosure,
    prompt_injection,
    prompt_leakage,
    unbounded_consumption,
)
from redteam.client import AgentClient  # noqa: E402
from report.schema import (  # noqa: E402
    AttackResult,
    RunMetadata,
    RunReport,
    utc_now_iso,
)

# Ordered so the flagship finding runs while the ledger is freshly reset.
ATTACKS = [
    excessive_agency,
    prompt_injection,
    info_disclosure,
    prompt_leakage,
    unbounded_consumption,
]

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(REPO_ROOT, "reports", "attack_results.json")

ROW = "{:<34} {:<12} {:<10} {}"


def _print_header(metadata: RunMetadata) -> None:
    print("=" * 100)
    print("PaySentry -- OWASP Top 10 for LLM Applications red-team run")
    print("=" * 100)
    print(f"target      : {metadata.base_url}")
    print(f"provider    : {metadata.target_provider}")
    print(f"model       : {metadata.target_model}")
    print(f"started     : {metadata.started_at}")
    if not metadata.is_valid_security_run:
        print()
        print("!! WARNING: target is not backed by a real LLM. This run")
        print("!! verifies plumbing only and produces NO valid findings.")
    print("-" * 100)
    print(ROW.format("OWASP CATEGORY", "RESULT", "TIME", "EVIDENCE"))
    print("-" * 100)


def _print_row(result: AttackResult) -> None:
    verdict = "VULNERABLE" if result.succeeded else "SECURE"
    category = result.owasp_category.split(":")[0]
    label = f"{category}: {result.owasp_category.split(': ', 1)[-1]}"
    print(
        ROW.format(
            label[:33],
            verdict,
            f"{result.duration_seconds:.1f}s",
            result.evidence[:120],
        )
    )


def run_all(base_url: str) -> RunReport:
    client = AgentClient(base_url)

    # Fail fast with a useful message rather than a stack trace per attack.
    try:
        health = client.health()
    except Exception as exc:  # noqa: BLE001
        print(f"Cannot reach the target agent at {base_url}: {exc}")
        print("Start it first with:  python target_agent/run_agent.py")
        raise SystemExit(2) from exc

    metadata = RunMetadata(
        started_at=utc_now_iso(),
        base_url=base_url,
        target_provider=health.get("provider", "unknown"),
        target_model=health.get("model", "unknown"),
    )

    # Clean ledger and session state so results are attributable to this run.
    client.reset()

    _print_header(metadata)
    started = time.time()
    results: list[AttackResult] = []

    for module in ATTACKS:
        try:
            result = module.run(base_url)
        except Exception as exc:  # noqa: BLE001
            # One broken attack must not lose the other four.
            result = AttackResult(
                owasp_category=getattr(module, "OWASP_CATEGORY", module.__name__),
                attack_name=getattr(module, "ATTACK_NAME", "unknown"),
                prompts_sent=[],
                agent_responses=[],
                succeeded=False,
                evidence=f"attack crashed: {type(exc).__name__}: {exc}",
                notes="Inconclusive -- the probe errored, this is not a pass.",
                error=traceback.format_exc(limit=3),
            )
        results.append(result)
        _print_row(result)

    metadata.duration_seconds = round(time.time() - started, 2)
    return RunReport(metadata=metadata, results=results)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    report = run_all(base_url)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as handle:
        handle.write(report.to_json())

    print("-" * 100)
    print(
        f"{report.vulnerable_count}/{report.total_count} categories VULNERABLE, "
        f"{report.total_count - report.vulnerable_count}/{report.total_count} secure "
        f"({report.metadata.duration_seconds:.1f}s total)"
    )

    flagship = next(
        (r for r in report.results if r.owasp_category.startswith("LLM06")), None
    )
    if flagship is not None:
        print()
        print("FLAGSHIP -- LLM06 Excessive Agency:", flagship.verdict)
        print(f"  {flagship.evidence}")

    errored = [r for r in report.results if r.error]
    if errored:
        print()
        print(f"WARNING: {len(errored)} attack(s) errored and are inconclusive:")
        for r in errored:
            print(f"  - {r.owasp_category}: {r.evidence}")

    print()
    print(f"Results written to {os.path.relpath(OUTPUT_PATH, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
