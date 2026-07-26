"""Summarise a garak run into per-probe pass/fail counts.

garak's own HTML report is the primary Stage 4 artifact, but it is a standalone
page. This reduces the raw .jsonl to a compact structure so the Stage 5
scorecard can cite the garak run alongside the hand-rolled findings instead of
leaving the two disconnected.

Usage:
    python redteam/garak_summary.py [path/to/garak.report.jsonl]
"""

from __future__ import annotations

import collections
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_JSONL = os.path.join(REPO_ROOT, "reports", "garak.report.jsonl")
OUTPUT_JSON = os.path.join(REPO_ROOT, "reports", "garak_summary.json")


def summarise(jsonl_path: str) -> dict:
    """Aggregate eval records into {probe: {detector: {passed, total}}}.

    garak writes several record types to the same file; `eval` entries carry
    the scored results, so everything else is skipped.
    """
    per_probe: dict[str, dict[str, dict[str, int]]] = collections.defaultdict(dict)
    run_meta: dict = {}

    with open(jsonl_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            entry_type = record.get("entry_type")
            if entry_type in {"start_run setup", "init"}:
                run_meta.update(
                    {
                        k: v
                        for k, v in record.items()
                        if k in {"garak_version", "start_time", "run"}
                    }
                )
            elif entry_type == "eval":
                probe = record.get("probe", "unknown")
                detector = record.get("detector", "unknown")
                passed = int(record.get("passed", 0))
                total = int(record.get("total", 0))
                per_probe[probe][detector] = {"passed": passed, "total": total}

    probes = []
    total_prompts = 0
    total_hits = 0
    for probe, detectors in sorted(per_probe.items()):
        detector_rows = []
        for detector, counts in sorted(detectors.items()):
            failed = counts["total"] - counts["passed"]
            detector_rows.append(
                {
                    "detector": detector,
                    "passed": counts["passed"],
                    "total": counts["total"],
                    "hits": failed,
                    "failure_rate": (
                        round(failed / counts["total"], 3) if counts["total"] else 0.0
                    ),
                }
            )
            total_prompts += counts["total"]
            total_hits += failed
        probes.append({"probe": probe, "detectors": detector_rows})

    return {
        "run": run_meta,
        "probes": probes,
        "totals": {
            "probe_count": len(probes),
            "scored_prompts": total_prompts,
            "detector_hits": total_hits,
        },
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    jsonl_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_JSONL
    if not os.path.exists(jsonl_path):
        print(f"No garak report found at {jsonl_path}")
        print("Run:  python redteam/run_garak.py")
        return 2

    summary = summarise(jsonl_path)

    print(f"garak probes scored: {summary['totals']['probe_count']}")
    print(f"prompts scored     : {summary['totals']['scored_prompts']}")
    print(f"detector hits      : {summary['totals']['detector_hits']}")
    print()
    for probe in summary["probes"]:
        print(probe["probe"])
        for row in probe["detectors"]:
            verdict = "PASS" if row["hits"] == 0 else "FAIL"
            print(
                f"   {verdict}  {row['detector']:<38} "
                f"{row['passed']}/{row['total']} ok "
                f"(failure rate {row['failure_rate']:.0%})"
            )

    with open(OUTPUT_JSON, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    print()
    print(f"Wrote {os.path.relpath(OUTPUT_JSON, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
