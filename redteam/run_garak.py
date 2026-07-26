"""Stage 4: run NVIDIA's garak scanner against the target agent.

WHY GARAK LIVES IN ITS OWN VIRTUALENV
-------------------------------------
garak cannot be installed alongside the target agent. It pins `openai==0.28.1`
(the pre-1.0 API) plus a numpy downgrade and the `typing` backport that
shadows the stdlib module. Installing it into the main environment downgrades
openai 2.43.0 -> 0.28.1 and breaks langchain-openai, i.e. it destroys the very
agent we are trying to scan. Verified with:

    pip install --dry-run --only-binary :all: garak
    -> Would install ... garak-0.9.0.11.post1 numpy-1.26.4 openai-0.28.1
       typing-3.7.4.1 ...

(A plain `pip install garak` fails even earlier: a transitive dependency
builds native extensions and needs a Rust/MSVC toolchain that isn't present.
`--only-binary :all:` sidesteps that by taking prebuilt wheels only.)

Since garak reaches the target over HTTP via its REST generator, it does not
need to share an environment with it. So we quarantine it in .venv-garak and
shell out. The isolation is the fix, not a workaround.

KNOWN UPSTREAM BUGS WORKED AROUND
---------------------------------
1. Hardcoded 10s HTTP timeout -- patched in redteam/garak_launcher.py. Without
   it most probes time out against a reasoning model and report a false SECURE.

2. `--parallel_attempts > 1` crashes on Windows:

       File "garak/probes/base.py", line 97, in _execute_attempt
         _config.transient.reportfile.write(...)
       AttributeError: 'NoneType' object has no attribute 'write'

   Windows multiprocessing uses spawn, so pool workers start with a fresh
   module state and never inherit the parent's open report file handle. There
   is no config-level fix, so parallelism is off by default. It would have been
   nice to have: the target has no rate limiting (our own LLM10 finding), so
   nothing server-side stops a concurrent scan -- only garak does.

COST CONTROL
------------
Every garak prompt is a live gpt-5.2 call. Full probe families run into
thousands of prompts, which is real money and a long wait for a demo. This
script therefore defaults to a small curated probe set and 1 generation per
prompt. Widen it deliberately with --probes, not by accident.

Usage:
    python redteam/run_garak.py                 # curated probe set
    python redteam/run_garak.py --probes dan.Dan_11_0
    python redteam/run_garak.py --list          # show available probes
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(REPO_ROOT, ".venv-garak", "Scripts", "python.exe")
if not os.path.exists(VENV_PYTHON):  # POSIX layout
    VENV_PYTHON = os.path.join(REPO_ROOT, ".venv-garak", "bin", "python")

CONFIG_PATH = os.path.join(REPO_ROOT, "garak_config.json")
# Thin wrapper executed by the venv interpreter; patches an upstream timeout
# bug before delegating to garak's CLI. See garak_launcher.py for detail.
LAUNCHER = os.path.join(REPO_ROOT, "redteam", "garak_launcher.py")
REPORTS_DIR = os.path.join(REPO_ROOT, "reports")
REPORT_PREFIX = os.path.join(REPORTS_DIR, "garak")
FINAL_HTML = os.path.join(REPORTS_DIR, "garak_report.html")

# Curated for signal per token spent. Each maps onto something the hand-rolled
# suite also covers, so the two can be compared:
#   promptinject.*  -> LLM01, cross-checks our prompt_injection.py
#   encoding.*      -> LLM01 via obfuscation, which our suite does NOT cover
#   dan.*           -> jailbreak/persona override, also uncovered by our suite
# Prompt counts are noted because each one is a paid gpt-5.2 call; the full
# non-Mini variants run to thousands and are not demo-appropriate.
DEFAULT_PROBES = [
    "encoding.InjectBase64",  # 77 prompts
    "dan.Dan_11_0",  # 1
    "dan.AntiDAN",  # 1
    "dan.DUDE",  # 1
    "promptinject.HijackHateHumansMini",  # 100
]  # 180 prompts total


def _require_venv() -> None:
    if not os.path.exists(VENV_PYTHON):
        print("garak virtualenv not found at .venv-garak")
        print("Create it with:")
        print("    python -m venv .venv-garak")
        print("    .venv-garak/Scripts/python -m pip install --only-binary :all: garak")
        raise SystemExit(2)


def _run(args: list[str]) -> int:
    print("+ " + " ".join(args))
    print("-" * 100)
    return subprocess.call(args, cwd=REPO_ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probes",
        default=",".join(DEFAULT_PROBES),
        help="comma-separated garak probes (default: curated small set)",
    )
    parser.add_argument(
        "--generations", type=int, default=1, help="generations per prompt"
    )
    parser.add_argument(
        "--parallel-attempts",
        type=int,
        default=1,
        dest="parallel_attempts",
        help=(
            "probe attempts to run concurrently. MUST stay 1 on Windows: "
            "garak 0.9.0.11 crashes with >1 (see module docstring). Sequential "
            "runs at roughly 5s/prompt."
        ),
    )
    parser.add_argument(
        "--list", action="store_true", help="list available probes and exit"
    )
    args = parser.parse_args()

    _require_venv()
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if args.list:
        return _run([VENV_PYTHON, LAUNCHER, "--list_probes"])

    exit_code = _run(
        [
            VENV_PYTHON,
            LAUNCHER,
            "--model_type",
            "rest",
            "--generator_option_file",
            CONFIG_PATH,
            "--probes",
            args.probes,
            "--generations",
            str(args.generations),
            "--parallel_attempts",
            str(args.parallel_attempts),
            "--report_prefix",
            REPORT_PREFIX,
        ]
    )

    # garak writes <prefix>.report.html; normalise to the documented filename.
    produced = f"{REPORT_PREFIX}.report.html"
    if os.path.exists(produced):
        shutil.copyfile(produced, FINAL_HTML)
        print()
        print(f"HTML report: {os.path.relpath(FINAL_HTML, REPO_ROOT)}")
    else:
        print()
        print(f"WARNING: expected {produced} was not produced.")

    return exit_code


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
