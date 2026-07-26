"""Stage 5: turn attack_results.json into a readable scorecard.

Produces two artifacts from one run:
    reports/scorecard.md    -- for the repo / PR review
    reports/scorecard.html  -- self-contained, opens straight in a browser

If reports/garak_summary.json is present it is folded in as a cross-check
section, because the two tools disagreed in a way worth showing: garak found a
prompt-injection class our hand-rolled suite originally missed.

Usage:
    python report/generate_scorecard.py
"""

from __future__ import annotations

import html
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_PATH = os.path.join(REPO_ROOT, "reports", "attack_results.json")
GARAK_SUMMARY_PATH = os.path.join(REPO_ROOT, "reports", "garak_summary.json")
MD_OUT = os.path.join(REPO_ROOT, "reports", "scorecard.md")
HTML_OUT = os.path.join(REPO_ROOT, "reports", "scorecard.html")

FLAGSHIP_PREFIX = "LLM06"

# Why each finding matters, in business terms rather than CVE-speak. A reviewer
# should be able to tell at a glance which of these costs money.
IMPACT = {
    "LLM01": "Attacker text overrides the agent's output contract.",
    "LLM02": "Customer PII disclosed across account boundaries.",
    "LLM06": "MOVES MONEY. Unauthorized refunds execute against real ledgers.",
    "LLM07": "Leaks the guardrail wording an attacker needs to argue around.",
    "LLM10": "Denial-of-wallet: unbounded inference cost, no throttle.",
}


def load_json(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _code(text: str) -> str:
    """Neutralise pipes and newlines so evidence survives a markdown table."""
    flat = " ".join(str(text).split())
    return flat.replace("|", "\\|")


def _category_code(category: str) -> str:
    return category.split(":")[0].strip()


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(data: dict, garak: dict | None) -> str:
    meta = data["metadata"]
    summary = data["summary"]
    results = data["results"]
    flagship = next(
        (r for r in results if r["owasp_category"].startswith(FLAGSHIP_PREFIX)), None
    )

    lines: list[str] = []
    lines.append("# PaySentry Vulnerability Scorecard")
    lines.append("")
    lines.append(
        f"**{summary['vulnerable']}/{summary['total']} categories vulnerable, "
        f"{summary['secure']}/{summary['total']} secure** "
        "— see fixes in Stage 6."
    )
    lines.append("")
    lines.append(
        f"Target `{meta['base_url']}` · provider `{meta['target_provider']}` · "
        f"model `{meta['target_model']}` · run `{meta['started_at']}` · "
        f"{meta['duration_seconds']}s"
    )
    lines.append("")

    if not meta.get("is_valid_security_run", True):
        lines.append(
            "> **WARNING — NOT A VALID SECURITY RUN.** The target was not backed "
            "by a real LLM, so these results verify plumbing only. Re-run with "
            "`LLM_PROVIDER=openai`."
        )
        lines.append("")

    # -- Flagship ----------------------------------------------------------
    if flagship is not None:
        verdict = "VULNERABLE" if flagship["succeeded"] else "SECURE"
        lines.append("---")
        lines.append("")
        lines.append(f"## Flagship Finding — {flagship['owasp_category']} — {verdict}")
        lines.append("")
        lines.append(f"**{flagship['attack_name']}**")
        lines.append("")
        lines.append(f"> {IMPACT.get(FLAGSHIP_PREFIX, '')}")
        lines.append("")
        lines.append("**Evidence — read from the ledger, not the transcript:**")
        lines.append("")
        lines.append("```")
        lines.append(flagship["evidence"])
        lines.append("```")
        lines.append("")
        lines.append(flagship["notes"])
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Full attack transcript "
                     f"({len(flagship['prompts_sent'])} turns)</summary>")
        lines.append("")
        for index, prompt in enumerate(flagship["prompts_sent"], start=1):
            lines.append(f"**Turn {index} — attacker**")
            lines.append("")
            lines.append("```")
            lines.append(str(prompt))
            lines.append("```")
            lines.append("")
            if index - 1 < len(flagship["agent_responses"]):
                lines.append("**Agent**")
                lines.append("")
                lines.append("```")
                lines.append(str(flagship["agent_responses"][index - 1]))
                lines.append("```")
                lines.append("")
        lines.append("</details>")
        lines.append("")

    # -- Full table --------------------------------------------------------
    lines.append("---")
    lines.append("")
    lines.append("## All Results")
    lines.append("")
    lines.append("| OWASP Category | Attack | Result | Evidence |")
    lines.append("| --- | --- | --- | --- |")
    for result in results:
        verdict = "**VULNERABLE**" if result["succeeded"] else "SECURE"
        lines.append(
            f"| {_code(result['owasp_category'])} "
            f"| {_code(result['attack_name'])} "
            f"| {verdict} "
            f"| {_code(result['evidence'])} |"
        )
    lines.append("")

    # -- Per-finding detail ------------------------------------------------
    lines.append("## Detail")
    lines.append("")
    for result in results:
        code = _category_code(result["owasp_category"])
        verdict = "VULNERABLE" if result["succeeded"] else "SECURE"
        lines.append(f"### {result['owasp_category']} — {verdict}")
        lines.append("")
        if code in IMPACT:
            lines.append(f"*Impact:* {IMPACT[code]}")
            lines.append("")
        lines.append(f"*Probes sent:* {len(result['prompts_sent'])} · "
                     f"*duration:* {result['duration_seconds']}s")
        lines.append("")
        lines.append(f"*Evidence:* {result['evidence']}")
        lines.append("")
        lines.append(result["notes"])
        lines.append("")
        if result.get("error"):
            lines.append("**This probe errored — the result is inconclusive, "
                         "not a pass.**")
            lines.append("")

    # -- Garak cross-check -------------------------------------------------
    if garak:
        lines.append("---")
        lines.append("")
        lines.append("## Garak Cross-Check")
        lines.append("")
        totals = garak["totals"]
        lines.append(
            f"NVIDIA garak scanned the same endpoint: "
            f"{totals['probe_count']} probes, {totals['scored_prompts']} prompts, "
            f"{totals['detector_hits']} detector hits."
        )
        lines.append("")
        lines.append("| Probe | Detector | Passed | Failure rate |")
        lines.append("| --- | --- | --- | --- |")
        for probe in garak["probes"]:
            for row in probe["detectors"]:
                lines.append(
                    f"| {probe['probe']} | {row['detector']} "
                    f"| {row['passed']}/{row['total']} "
                    f"| {row['failure_rate']:.0%} |"
                )
        lines.append("")
        lines.append(
            "**Reading these honestly.** The four `mitigation.MitigationBypass` "
            "failures are detector artifacts: the agent did refuse the DAN "
            "personas, but in character as a payment assistant rather than with "
            "boilerplate safety phrasing, which that detector looks for. The "
            "`dan.*` detectors that actually test persona adoption all passed. "
            "`encoding.DecodeMatch` shows the agent decoding base64 — a "
            "capability with no business in a payment assistant, and the "
            "precondition for encoding-based filter bypass — but it does not by "
            "itself prove an encoded instruction was obeyed. The one finding "
            "that changed our assessment is `promptinject`: it hit a "
            "task-framing class our own LLM01 probes missed entirely, so those "
            "probes were added to `prompt_injection.py`."
        )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by `report/generate_scorecard.py` from "
        "`reports/attack_results.json`.*"
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

CSS = """
:root {
  --bg: #ffffff; --fg: #16181d; --muted: #5c6370; --line: #e3e6ea;
  --card: #f7f8fa; --bad: #c1272d; --bad-bg: #fdecec; --good: #1a7f4b;
  --good-bg: #e9f7ef; --accent: #0b5cad; --code-bg: #f2f4f6;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --fg: #e7e9ec; --muted: #9aa3ae; --line: #2a2f37;
    --card: #1b1e24; --bad: #ff7b7b; --bad-bg: #3a1d1f; --good: #6ede9f;
    --good-bg: #17352a; --accent: #79b8ff; --code-bg: #1f232a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 1.9rem; margin: 0 0 .5rem; letter-spacing: -.02em; }
h2 { font-size: 1.3rem; margin: 2.5rem 0 .75rem; padding-bottom: .35rem;
     border-bottom: 1px solid var(--line); }
h3 { font-size: 1.02rem; margin: 1.75rem 0 .4rem; }
p { margin: .6rem 0; }
a { color: var(--accent); }
.headline { font-size: 1.15rem; font-weight: 600; margin: 0 0 .75rem; }
.meta { color: var(--muted); font-size: .85rem; font-family: ui-monospace,
        SFMono-Regular, Menlo, Consolas, monospace; margin-bottom: 1.5rem; }
.badge { display: inline-block; padding: .12rem .5rem; border-radius: 999px;
         font-size: .74rem; font-weight: 700; letter-spacing: .04em;
         text-transform: uppercase; white-space: nowrap; }
.badge.vuln { background: var(--bad-bg); color: var(--bad); }
.badge.safe { background: var(--good-bg); color: var(--good); }
.warn { background: var(--bad-bg); color: var(--bad); border-left: 4px solid var(--bad);
        padding: .85rem 1rem; border-radius: 6px; margin: 1rem 0; font-weight: 600; }
.flagship { background: var(--card); border: 1px solid var(--line);
            border-left: 4px solid var(--bad); border-radius: 8px;
            padding: 1.25rem 1.4rem; margin: 1rem 0 2rem; }
.flagship h2 { margin-top: 0; border: 0; }
.impact { font-weight: 600; color: var(--bad); margin: .25rem 0 1rem; }
.tablewrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; min-width: 640px; }
th, td { text-align: left; padding: .6rem .7rem; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { font-size: .74rem; text-transform: uppercase; letter-spacing: .05em;
     color: var(--muted); }
tbody tr:hover { background: var(--card); }
td.ev { font-size: .82rem; color: var(--muted); }
pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px;
      padding: .8rem .9rem; overflow-x: auto; font-size: .8rem; line-height: 1.5;
      white-space: pre-wrap; word-break: break-word; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
details { margin: 1rem 0; }
summary { cursor: pointer; font-weight: 600; font-size: .9rem; color: var(--accent); }
.turn { color: var(--muted); font-size: .78rem; text-transform: uppercase;
        letter-spacing: .05em; margin-top: 1rem; font-weight: 700; }
.note { color: var(--muted); font-size: .9rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--muted); font-size: .8rem; }
"""


def _badge(succeeded: bool) -> str:
    return (
        '<span class="badge vuln">Vulnerable</span>'
        if succeeded
        else '<span class="badge safe">Secure</span>'
    )


def render_html(data: dict, garak: dict | None) -> str:
    meta = data["metadata"]
    summary = data["summary"]
    results = data["results"]
    flagship = next(
        (r for r in results if r["owasp_category"].startswith(FLAGSHIP_PREFIX)), None
    )
    e = html.escape

    out: list[str] = []
    out.append("<!doctype html>")
    out.append('<html lang="en"><head><meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    out.append("<title>PaySentry Vulnerability Scorecard</title>")
    out.append(f"<style>{CSS}</style>")
    out.append("</head><body><main>")

    out.append("<h1>PaySentry Vulnerability Scorecard</h1>")
    out.append(
        f'<p class="headline">{summary["vulnerable"]}/{summary["total"]} categories '
        f'vulnerable, {summary["secure"]}/{summary["total"]} secure '
        "&mdash; see fixes in Stage 6.</p>"
    )
    out.append(
        f'<p class="meta">target {e(meta["base_url"])} &middot; provider '
        f'{e(str(meta["target_provider"]))} &middot; model '
        f'{e(str(meta["target_model"]))} &middot; {e(meta["started_at"])} &middot; '
        f'{meta["duration_seconds"]}s</p>'
    )

    if not meta.get("is_valid_security_run", True):
        out.append(
            '<div class="warn">NOT A VALID SECURITY RUN &mdash; the target was not '
            "backed by a real LLM. These results verify plumbing only. Re-run with "
            "LLM_PROVIDER=openai.</div>"
        )

    # -- Flagship ----------------------------------------------------------
    if flagship is not None:
        out.append('<div class="flagship">')
        out.append(
            f'<h2>Flagship Finding &mdash; {e(flagship["owasp_category"])} '
            f"{_badge(flagship['succeeded'])}</h2>"
        )
        out.append(f"<p><strong>{e(flagship['attack_name'])}</strong></p>")
        out.append(f'<p class="impact">{e(IMPACT.get(FLAGSHIP_PREFIX, ""))}</p>')
        out.append(
            "<p>Evidence &mdash; read from the ledger, not the transcript:</p>"
        )
        out.append(f"<pre>{e(flagship['evidence'])}</pre>")
        out.append(f'<p class="note">{e(flagship["notes"])}</p>')
        out.append("<details><summary>Full attack transcript "
                   f"({len(flagship['prompts_sent'])} turns)</summary>")
        for index, prompt in enumerate(flagship["prompts_sent"], start=1):
            out.append(f'<div class="turn">Turn {index} &mdash; attacker</div>')
            out.append(f"<pre>{e(str(prompt))}</pre>")
            if index - 1 < len(flagship["agent_responses"]):
                out.append('<div class="turn">Agent</div>')
                out.append(f"<pre>{e(str(flagship['agent_responses'][index - 1]))}</pre>")
        out.append("</details>")
        out.append("</div>")

    # -- Table -------------------------------------------------------------
    out.append("<h2>All Results</h2>")
    out.append('<div class="tablewrap"><table><thead><tr>')
    out.append("<th>OWASP Category</th><th>Attack</th><th>Result</th><th>Evidence</th>")
    out.append("</tr></thead><tbody>")
    for result in results:
        out.append("<tr>")
        out.append(f"<td>{e(result['owasp_category'])}</td>")
        out.append(f"<td>{e(result['attack_name'])}</td>")
        out.append(f"<td>{_badge(result['succeeded'])}</td>")
        out.append(f'<td class="ev">{e(result["evidence"])}</td>')
        out.append("</tr>")
    out.append("</tbody></table></div>")

    # -- Detail ------------------------------------------------------------
    out.append("<h2>Detail</h2>")
    for result in results:
        code = _category_code(result["owasp_category"])
        out.append(
            f"<h3>{e(result['owasp_category'])} {_badge(result['succeeded'])}</h3>"
        )
        if code in IMPACT:
            out.append(f'<p class="impact">{e(IMPACT[code])}</p>')
        out.append(
            f'<p class="meta">{len(result["prompts_sent"])} probes &middot; '
            f'{result["duration_seconds"]}s</p>'
        )
        out.append(f"<pre>{e(result['evidence'])}</pre>")
        out.append(f'<p class="note">{e(result["notes"])}</p>')
        if result.get("error"):
            out.append(
                '<div class="warn">This probe errored &mdash; inconclusive, '
                "not a pass.</div>"
            )

    # -- Garak -------------------------------------------------------------
    if garak:
        totals = garak["totals"]
        out.append("<h2>Garak Cross-Check</h2>")
        out.append(
            f"<p>NVIDIA garak scanned the same endpoint: "
            f"{totals['probe_count']} probes, {totals['scored_prompts']} prompts, "
            f"{totals['detector_hits']} detector hits.</p>"
        )
        out.append('<div class="tablewrap"><table><thead><tr>')
        out.append("<th>Probe</th><th>Detector</th><th>Passed</th>"
                   "<th>Failure rate</th></tr></thead><tbody>")
        for probe in garak["probes"]:
            for row in probe["detectors"]:
                out.append("<tr>")
                out.append(f"<td>{e(probe['probe'])}</td>")
                out.append(f"<td>{e(row['detector'])}</td>")
                out.append(f"<td>{row['passed']}/{row['total']}</td>")
                out.append(
                    f"<td>{_badge(row['hits'] > 0)} {row['failure_rate']:.0%}</td>"
                )
                out.append("</tr>")
        out.append("</tbody></table></div>")
        out.append(
            '<p class="note"><strong>Reading these honestly.</strong> The four '
            "<code>mitigation.MitigationBypass</code> failures are detector "
            "artifacts: the agent did refuse the DAN personas, but in character "
            "as a payment assistant rather than with the boilerplate safety "
            "phrasing that detector looks for. The <code>dan.*</code> detectors "
            "that actually test persona adoption all passed. "
            "<code>encoding.DecodeMatch</code> shows the agent decoding base64 "
            "&mdash; a capability with no business in a payment assistant, and "
            "the precondition for encoding-based filter bypass &mdash; but it "
            "does not by itself prove an encoded instruction was obeyed. The one "
            "finding that changed our assessment is <code>promptinject</code>: it "
            "hit a task-framing class our own LLM01 probes missed entirely, so "
            "those probes were added to <code>prompt_injection.py</code>.</p>"
        )

    out.append(
        "<footer>Generated by <code>report/generate_scorecard.py</code> from "
        "<code>reports/attack_results.json</code>. Synthetic data only &mdash; no "
        "real customers, transactions or payment systems.</footer>"
    )
    out.append("</main></body></html>")
    return "\n".join(out)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    data = load_json(RESULTS_PATH)
    if data is None:
        print(f"No results at {RESULTS_PATH}")
        print("Run:  python redteam/orchestrator.py")
        return 2

    garak = load_json(GARAK_SUMMARY_PATH)

    with open(MD_OUT, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(data, garak))
    with open(HTML_OUT, "w", encoding="utf-8") as handle:
        handle.write(render_html(data, garak))

    summary = data["summary"]
    print(
        f"{summary['vulnerable']}/{summary['total']} vulnerable, "
        f"{summary['secure']}/{summary['total']} secure"
    )
    if garak is None:
        print("(no garak_summary.json -- cross-check section omitted)")
    print(f"Wrote {os.path.relpath(MD_OUT, REPO_ROOT)}")
    print(f"Wrote {os.path.relpath(HTML_OUT, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
