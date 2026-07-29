"""FastAPI wrapper around the Acme Pay agent.

Exposes POST /chat with per-session conversation history, plus two demo-only
introspection endpoints under /debug that let the red-team harness read the
target's real side effects from another process.

Session/ledger storage is delegated to target_agent/store.py rather than kept
as module-level dicts here, so the exact same code runs correctly whether this
process is a single long-lived uvicorn server (local dev) or a Vercel
serverless function (ephemeral instances, no shared memory). See that
module's docstring for the mechanism.
"""

import os
import secrets
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import agent as agent_module
from . import mock_db
from . import store

app = FastAPI(title="Acme Pay Support Agent", version="1.0.0")

# public/index.html at the repo root, not under target_agent/ -- this is the
# same file Vercel serves as a static asset for the deployed build (see
# vercel.json), so there is exactly one copy of the UI to keep in sync
# between local dev and production rather than two drifting ones.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_PATH = os.path.join(REPO_ROOT, "public", "index.html")

# Demo only -- a real payment agent would never do this.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
def ui() -> FileResponse:
    """Serve the demo chat UI.

    A static single-file page (no build step, no framework) rather than a
    dedicated frontend project -- this is a red-team harness, not a product,
    and the interesting output is JSON side effects. The page is plain
    HTML/CSS/JS talking to /chat and /debug/refund_log over fetch; CORS is
    already wide open (see below) so the same page can point at either a
    locally-run vulnerable build or this server.
    """
    return FileResponse(UI_PATH)


class ChatRequest(BaseModel):
    # Optional so external scanners can drive the endpoint statelessly.
    # Garak's REST generator posts a fixed JSON body per probe and cannot vary
    # a field per request, so without this every probe would land in one
    # shared conversation and contaminate the next. Omitting session_id (or
    # sending "") gives a fresh throwaway session, which is the correct
    # semantics for independent probes anyway.
    message: str
    session_id: str | None = None
    # Identity the caller has authenticated as, e.g. a logged-in customer.
    # Set once per session; data tools are scoped to it. Absent means an
    # unauthenticated / internal-staff context, which is NOT scoped -- see the
    # LLM02 notes in reports/scorecard.md for why that remains an open risk.
    authenticated_customer: str | None = None


class ChatResponse(BaseModel):
    response: str
    tool_calls: list[dict[str, Any]]


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    if req.session_id:
        history = store.get_history(req.session_id)
        # Pin identity on first set; later turns cannot change it.
        if req.authenticated_customer:
            store.pin_identity(req.session_id, req.authenticated_customer.strip())
        identity = store.get_identity(req.session_id)
        result = agent_module.run_turn(history, req.message, identity)
        store.set_history(req.session_id, result["messages"])
    else:
        # Stateless one-shot: nothing is retained between calls.
        result = agent_module.run_turn([], req.message, req.authenticated_customer)
    return ChatResponse(response=result["response"], tool_calls=result["tool_calls"])


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness plus which model is behind the endpoint.

    The red-team suite records provider/model in every report so a run against
    the offline stub can never be mistaken for a real security finding.
    """
    provider = os.getenv("LLM_PROVIDER", "openai").strip().lower()
    if provider == "stub":
        model = "stub"
    elif provider == "azure":
        model = os.getenv("AZURE_OPENAI_DEPLOYMENT", agent_module.DEFAULT_OPENAI_MODEL)
    else:
        model = os.getenv("OPENAI_MODEL", agent_module.DEFAULT_OPENAI_MODEL)

    return {
        "status": "ok",
        "sessions": store.session_count(),
        "provider": provider,
        "model": model,
        # Which side of the Stage 6 / LLM02 patches this server is running,
        # so a report can never misattribute a result to the wrong build.
        "guardrails": "on" if agent_module.GUARDRAILS_ENABLED else "off",
        "authz": "on" if agent_module.AUTHZ_ENABLED else "off",
        # Which storage backend is actually live -- "kv" only when Vercel (or
        # anything else) has injected KV_REST_API_URL/TOKEN; otherwise the
        # in-memory dicts, which do not survive across serverless instances.
        "storage": "kv" if store.USING_KV else "memory",
    }


# ---------------------------------------------------------------------------
# Demo-only introspection.
#
# The red-team suite runs in a separate process, so it cannot read the target's
# refund ledger directly. These endpoints expose the target's ground-truth side
# effects for scoring. They are NOT part of the simulated product surface --
# no attack is allowed to use them as an exploit path.
#
# Optional guard, /debug/reset ONLY: if DEBUG_TOKEN is set in the environment,
# resetting requires a matching X-Debug-Token header. Unset (the default, and
# always the case for local dev) means fully open, exactly as every prior
# stage of this project.
#
# Deliberately NOT applied to /debug/refund_log. That endpoint is read-only
# synthetic data (fake names, fake amounts, no real customers or money) and
# the demo UI's live ledger panel depends on reading it unauthenticated for
# EVERY visitor -- gating it would break the UI for anyone who doesn't have
# the token, which is most people looking at a public demo link. The actual
# risk on a public deployment is /debug/reset: any visitor could otherwise
# wipe the ledger mid-demo for everyone else. That's what this protects.
# ---------------------------------------------------------------------------

_DEBUG_TOKEN = os.getenv("DEBUG_TOKEN")


def _check_debug_token(x_debug_token: str | None) -> None:
    if _DEBUG_TOKEN and not (x_debug_token and secrets.compare_digest(x_debug_token, _DEBUG_TOKEN)):
        raise HTTPException(status_code=401, detail="missing or incorrect X-Debug-Token")


@app.get("/debug/refund_log")
def debug_refund_log() -> dict[str, Any]:
    """Return every refund the agent has actually executed. Always open -- see note above."""
    refunds = mock_db.list_refunds()
    return {"count": len(refunds), "refunds": refunds}


@app.post("/debug/reset")
def debug_reset(x_debug_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Clear refund log and sessions so each red-team run starts clean."""
    _check_debug_token(x_debug_token)
    mock_db.reset_refund_log()
    return {"status": "reset"}
