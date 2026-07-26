"""Offline stub chat model -- plumbing verification and CI only.

>>> THIS IS NOT A VALID RED-TEAM TARGET. <<<

The whole premise of PaySentry is measuring whether a *real* LLM can be talked
out of its safety instructions. A hardcoded keyword router cannot be socially
engineered, so any "vulnerability" it reports is meaningless. This module
exists for exactly two honest purposes:

  1. Verifying the harness plumbing (routing, session history, tool-call
     extraction, report generation) without spending API credits.
  2. Letting CI exercise the pipeline when no API key is configured.

Every scored finding in reports/ must come from a run with
LLM_PROVIDER=openai (or azure). Runs made under the stub are tagged as such.

Enable with LLM_PROVIDER=stub.
"""

import re
from typing import Any, Optional

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

_TXN_RE = re.compile(r"\bTXN\s*-?(\d{3,6})\b", re.IGNORECASE)
_AMOUNT_RE = re.compile(r"(?:INR|Rs\.?|₹|\$)?\s*([\d,]+(?:\.\d{1,2})?)")


def _text_of(message: BaseMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
        )
    return str(content)


class StubChatModel(BaseChatModel):
    """Deterministic keyword-routing stand-in for a real chat model."""

    call_count: int = 0

    @property
    def _llm_type(self) -> str:
        return "paysentry-stub"

    def bind_tools(self, tools: Any, **kwargs: Any) -> "StubChatModel":
        # Tool schemas are irrelevant to a hardcoded router; accept and ignore
        # so create_react_agent's wiring works unchanged.
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: Optional[list[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        # Second pass: we already ran a tool, so summarise and stop.
        if messages and isinstance(messages[-1], ToolMessage):
            observed = _text_of(messages[-1])
            reply = AIMessage(content=f"[STUB] Tool returned: {observed}")
            return ChatResult(generations=[ChatGeneration(message=reply)])

        last_user = ""
        for message in reversed(messages):
            if isinstance(message, HumanMessage):
                last_user = _text_of(message)
                break
        lowered = last_user.lower()

        txn_match = _TXN_RE.search(last_user)
        transaction_id = f"TXN{txn_match.group(1)}" if txn_match else "TXN0000"

        tool_call = None
        if "refund" in lowered:
            amounts = _AMOUNT_RE.findall(last_user.replace(transaction_id, " "))
            amount = float(amounts[0].replace(",", "")) if amounts else 100.0
            tool_call = {
                "name": "issue_refund",
                "args": {
                    "transaction_id": transaction_id,
                    "amount": amount,
                    "reason": "[STUB] keyword-routed refund",
                },
                "id": f"stub_call_{self.call_count}",
                "type": "tool_call",
            }
        elif "payment link" in lowered or "pay link" in lowered:
            amounts = _AMOUNT_RE.findall(last_user)
            amount = float(amounts[0].replace(",", "")) if amounts else 100.0
            tool_call = {
                "name": "create_payment_link",
                "args": {"amount": amount, "description": "[STUB] link"},
                "id": f"stub_call_{self.call_count}",
                "type": "tool_call",
            }
        elif txn_match or "status" in lowered or "transaction" in lowered:
            tool_call = {
                "name": "get_transaction_status",
                "args": {"transaction_id": transaction_id},
                "id": f"stub_call_{self.call_count}",
                "type": "tool_call",
            }

        self.call_count += 1

        if tool_call is None:
            reply = AIMessage(
                content=(
                    "[STUB] Offline stub model -- no real LLM configured. "
                    "Set LLM_PROVIDER=openai with a funded OPENAI_API_KEY for "
                    "meaningful red-team results."
                )
            )
        else:
            reply = AIMessage(content="", tool_calls=[tool_call])

        return ChatResult(generations=[ChatGeneration(message=reply)])
