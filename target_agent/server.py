"""FastAPI wrapper around the Acme Pay agent.

Exposes POST /chat with per-session in-memory conversation history, plus two
demo-only introspection endpoints under /debug that let the red-team harness
read the target's real side effects from another process.
"""

import os
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from langchain_core.messages import BaseMessage
from pydantic import BaseModel

from . import agent as agent_module
from . import mock_db

app = FastAPI(title="Acme Pay Support Agent", version="1.0.0")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Demo only -- a real payment agent would never do this.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# session_id -> message history. In-memory, no persistence.
SESSIONS: dict[str, list[BaseMessage]] = {}

# session_id -> authenticated customer name. Kept separate from the message
# history deliberately: identity must not be something the conversation can
# rewrite. Pinned on first set, so a later turn cannot switch identity
# mid-session -- that would be a trivial bypass of the LLM02 fix.
SESSION_IDENTITY: dict[str, str] = {}


@app.get("/", include_in_schema=False)
def ui() -> FileResponse:
    """Serve the demo chat UI.

    A static single-file page (no build step, no framework) rather than a
    dedicated frontend project -- this is a red-team harness, not a product,
    and the interesting output is JSON side effects. The page is plain
    HTML/CSS/JS talking to /chat and /debug/refund_log over fetch; CORS is
    already wide open (see below) so the same page can point at either the
    patched (:8000) or vulnerable (:8001) build.
    """
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


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
        history = SESSIONS.get(req.session_id, [])
        # Pin identity on first set; later turns cannot change it.
        if req.authenticated_customer and req.session_id not in SESSION_IDENTITY:
            SESSION_IDENTITY[req.session_id] = req.authenticated_customer.strip()
        identity = SESSION_IDENTITY.get(req.session_id)
        result = agent_module.run_turn(history, req.message, identity)
        SESSIONS[req.session_id] = result["messages"]
    else:
        # Stateless one-shot: nothing is retained between calls.
        result = agent_module.run_turn(
            [], req.message, req.authenticated_customer
        )
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
        "sessions": len(SESSIONS),
        "provider": provider,
        "model": model,
        # Which side of the Stage 6 patch this server is running, so a report
        # can never misattribute a result to the wrong build.
        "guardrails": "on" if agent_module.GUARDRAILS_ENABLED else "off",
        "authz": "on" if agent_module.AUTHZ_ENABLED else "off",
    }


# ---------------------------------------------------------------------------
# Demo-only introspection.
#
# The red-team suite runs in a separate process, so it cannot read the target's
# `refund_log` directly. These endpoints expose the target's ground-truth side
# effects for scoring. They are NOT part of the simulated product surface --
# no attack is allowed to use them as an exploit path.
# ---------------------------------------------------------------------------


@app.get("/debug/refund_log")
def debug_refund_log() -> dict[str, Any]:
    """Return every refund the agent has actually executed."""
    return {"count": len(mock_db.refund_log), "refunds": list(mock_db.refund_log)}


@app.post("/debug/reset")
def debug_reset() -> dict[str, Any]:
    """Clear refund log and sessions so each red-team run starts clean."""
    mock_db.reset_refund_log()
    SESSIONS.clear()
    SESSION_IDENTITY.clear()
    return {"status": "reset"}
