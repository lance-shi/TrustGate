"""Run a local mock LLM/tool lifecycle: python examples/boundary_demo.py.

Requires the installed TrustGate package and local en_core_web_sm model.
All data below is synthetic. No API key, framework, or network is used.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from trustgate import (
    CrossSessionTokenError,
    DataReleaseDenied,
    EntityResolutionState,
    SessionClosedError,
    ToolCall,
    TrustGate,
)
from trustgate.models import JsonValue

POLICY_PATH = Path(__file__).resolve().with_name("sample-policy.yaml")


def _require(condition: bool) -> None:
    if not condition:
        raise RuntimeError("The demonstration checks failed.")


def _check_safe(value: JsonValue) -> None:
    """Guard these known fixtures; this is not a general sensitive-data detector."""
    rendered = json.dumps(value).casefold()
    # Whole words avoid treating a short name inside an opaque hex ID as a leak.
    _require(re.search(r"\b(?:ada|lovelace|12345678|joanna|joseph|taylor)\b", rendered) is None)


def mock_llm(safe_input: str, destination: str) -> ToolCall:
    """Only tokenized text reaches this mock; it has no session or vault access."""
    _check_safe(safe_input)
    people = re.findall(r"\[PERSON_[0-9a-f]{32}_[1-9][0-9]*\]", safe_input)
    accounts = re.findall(r"\[ACCOUNT_NUMBER_[0-9a-f]{32}_[1-9][0-9]*\]", safe_input)
    _require(len(people) == len(accounts) == 1)
    return ToolCall(name=destination, arguments={"owner": people[0], "account": accounts[0]})


def mock_tool(destination: str, arguments: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Trusted host-side mock receives approved raw arguments, never logs them.

    Both destinations are local simulations. The host owns execution; TrustGate
    only decides which values may be released to each destination.
    """
    _require(destination in {"get_account", "update_account"})
    _require(arguments == {"owner": "Ada Lovelace", "account": "12345678"})
    return {
        "status": "read_complete" if destination == "get_account" else "update_complete",
        "owners": [{"name": arguments["owner"], "account": arguments["account"]}],
        "Mr Lovelace": ["Ada", arguments["account"]],
        "empty": ["", {}, [], None],
    }


def mock_llm_reply(safe_result: JsonValue) -> str:
    """The LLM receives the sanitized tool result before producing a reply."""
    _check_safe(safe_result)
    return "The tool returned tokenized account data."


def run_demo() -> dict[str, JsonValue]:
    """Return only checked safe outputs and fixed lifecycle confirmations."""
    gate = TrustGate.from_yaml(POLICY_PATH)
    with gate.session(transcript=True) as session:
        safe_input = session.sanitize("Ada Lovelace has account 12345678.")
        _check_safe(safe_input)
        results: dict[str, JsonValue] = {}
        calls: list[JsonValue] = []
        replies: list[JsonValue] = []
        for destination in ("get_account", "update_account"):
            call = mock_llm(safe_input, destination)
            calls.append(call.model_dump(mode="json"))
            # Approved raw arguments and raw tool returns stay on the host side.
            arguments = session.rehydrate_for_tool(call)
            raw_result = mock_tool(destination, arguments)
            safe_result = session.sanitize_tool_result(raw_result)
            _check_safe(safe_result)
            results[destination] = safe_result
            replies.append(mock_llm_reply(safe_result))

        person_token = call.arguments["owner"]
        account_token = call.arguments["account"]
        for destination, result in results.items():
            status = "read_complete" if destination == "get_account" else "update_complete"
            _require(
                result
                == {
                    "status": status,
                    "owners": [{"name": person_token, "account": account_token}],
                    person_token: [person_token, account_token],
                    "empty": ["", {}, [], None],
                }
            )
        followup = session.sanitize("Mr Lovelace")
        _require(followup == person_token)

        safe_ambiguity = session.sanitize("Joanna Taylor met Joseph Taylor. Ask Jo Taylor.")
        _check_safe(safe_ambiguity)
        candidates = re.findall(r"\[PERSON_[0-9a-f]{32}_[1-9][0-9]*\]", safe_ambiguity)
        _require(len(candidates) == len(set(candidates)) == 3)
        ambiguity_event = gate.audit_sink.events[-1]
        _require(ambiguity_event.resolutions[-1].state is EntityResolutionState.AMBIGUOUS)
        _require(session.sanitize("Jo Taylor") == candidates[-1])

        try:
            session.rehydrate_for_tool(
                ToolCall(name="send_email", arguments={"owner": person_token})
            )
        except DataReleaseDenied:
            denied = True
        else:
            denied = False
        _require(denied)

        with gate.session() as other:
            try:
                other.rehydrate_for_tool(call)
            except CrossSessionTokenError:
                isolated = True
            else:
                isolated = False
        _require(isolated)

    _require(session.is_closed)
    try:
        session.rehydrate_for_tool(call)
    except SessionClosedError:
        closed_rejected = True
    else:
        closed_rejected = False
    _require(closed_rejected)

    # Original full audit events contain only metadata; include a compact view.
    events = gate.audit_sink.events
    _check_safe([event.model_dump(mode="json") for event in events])
    report: dict[str, JsonValue] = {
        "llm_input": safe_input,
        "llm_tool_calls": calls,
        "llm_tool_results": results,
        "llm_replies": replies,
        "followup": followup,
        "stable_person_token": True,
        "ambiguity": {"text": safe_ambiguity, "state": "ambiguous", "token": candidates[-1]},
        "denied_release": denied,
        "cross_session_rejected": isolated,
        "session_closed": session.is_closed,
        "closed_session_rejected": closed_rejected,
        "transcript": [entry.model_dump(mode="json") for entry in session.transcript],
        "audit_summary": {
            "event_count": len(events),
            "event_types": sorted({event.event_type.value for event in events}),
            "resolution_states": sorted(
                {item.state.value for event in events for item in event.resolutions}
            ),
        },
    }
    _check_safe(report)
    return report


def main() -> int:
    try:
        report = run_demo()
        _check_safe(report)
    except Exception:
        # Never print arbitrary exception text or a traceback from the host mock.
        print("Demo failed. Check the local model, policy, and demo tests.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
