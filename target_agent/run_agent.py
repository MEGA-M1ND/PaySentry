"""Entry point: start the target agent's HTTP server.

Usage:
    python target_agent/run_agent.py            # port 8000
    python target_agent/run_agent.py --port 8001

The port is configurable so the demo can run the patched build and the
vulnerable build (PAYSENTRY_GUARDRAILS=off) side by side, instead of
restarting the server mid-demo.

Runs standalone (not as `python -m`), so we put the repo root on sys.path
before importing the package.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn  # noqa: E402

from target_agent import agent as agent_module  # noqa: E402
from target_agent.server import app  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the Acme Pay target agent.")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PAYSENTRY_PORT", "8000")),
        help="port to listen on (default 8000, or $PAYSENTRY_PORT)",
    )
    args = parser.parse_args()

    guardrails = "ON" if agent_module.GUARDRAILS_ENABLED else "OFF (VULNERABLE BUILD)"
    print(f"Starting Acme Pay support agent on http://localhost:{args.port} ...")
    print(f"  guardrails: {guardrails}")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
