"""Exercise an installed distribution offline, outside the source checkout."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.resources
import json
import re
import socket
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

RAW_PERSON = "Ada Lovelace"
RAW_ACCOUNT = "12345678"
RAW_NAMES = ("Joanna Taylor", "Joseph Taylor", "Jo Taylor")


def _require(condition: bool) -> None:
    if not condition:
        raise RuntimeError("Installed distribution smoke validation failed.")


def _safe(value: object) -> None:
    rendered = json.dumps(value).casefold()
    for secret in (RAW_PERSON, RAW_ACCOUNT, *RAW_NAMES):
        _require(secret.casefold() not in rendered)


def run(model_path: Path) -> dict[str, object]:
    import trustgate
    from trustgate import (
        CrossSessionTokenError,
        DataReleaseDenied,
        DetectionUnavailableError,
        SessionClosedError,
        ToolCall,
        TrustGate,
        TrustSession,
    )
    from trustgate.detection import PresidioDetector

    prefix = Path(sys.prefix).resolve()
    origin = Path(trustgate.__file__).resolve()
    _require(sys.prefix != sys.base_prefix)
    _require(origin.is_relative_to(prefix))
    _require(importlib.resources.files("trustgate").joinpath("py.typed").is_file())
    direct = importlib.metadata.distribution("trustgate").read_text("direct_url.json")
    _require(not json.loads(direct or "{}").get("dir_info", {}).get("editable", False))
    configuration = (prefix / "pyvenv.cfg").read_text(encoding="utf-8").lower()
    _require("include-system-site-packages = true" not in configuration)
    _require(model_path.is_dir())
    attempts = []

    def no_network(*args, **kwargs):
        attempts.append(True)
        raise RuntimeError("Network access is disabled during release smoke validation.")

    # Model weights are an explicitly supplied local asset, never a download.
    with (
        patch.object(socket.socket, "connect", no_network),
        patch.object(socket, "create_connection", no_network),
    ):
        try:
            PresidioDetector(model_name="trustgate_release_model_not_installed")
        except DetectionUnavailableError as error:
            _safe(str(error))
            _require(error.__cause__ is error.__context__ is None)
        else:
            _require(False)
        detector = PresidioDetector(model_name=str(model_path))
        policy = (
            "version: 1\ndata_policies:\n"
            "  PERSON:\n    external_llm: tokenize\n"
            "    destinations: {get_account: allow, update_account: allow}\n"
            "  ACCOUNT_NUMBER:\n    external_llm: tokenize\n"
            "    destinations: {get_account: allow, update_account: allow}\n"
        )
        # Only non-sensitive policy configuration is written; mappings stay in memory.
        with tempfile.TemporaryDirectory(prefix="trustgate-smoke-policy-") as temporary:
            path = Path(temporary) / "policy.yaml"
            path.write_text(policy, encoding="utf-8")
            gate = TrustGate.from_yaml(path)
        with TrustSession(
            policy=gate.policy, detector=detector, audit_sink=gate.audit_sink, transcript=True
        ) as session:
            safe_input = session.sanitize(f"{RAW_PERSON} has account {RAW_ACCOUNT}.")
            _safe(safe_input)
            person = re.search(r"\[PERSON_[0-9a-f]{32}_[1-9][0-9]*\]", safe_input)
            account = re.search(r"\[ACCOUNT_NUMBER_[0-9a-f]{32}_[1-9][0-9]*\]", safe_input)
            _require(person is not None and account is not None)
            tokens = {"owner": person.group(), "account": account.group()}
            llm_seen = [safe_input]
            for destination in ("get_account", "update_account"):
                call = ToolCall(name=destination, arguments=tokens)
                raw_arguments = session.rehydrate_for_tool(call)
                _require(raw_arguments == {"owner": RAW_PERSON, "account": RAW_ACCOUNT})
                _require(call.arguments == tokens)
                raw_result = {"owners": [raw_arguments], RAW_PERSON: [RAW_ACCOUNT, "", None]}
                safe_result = session.sanitize_tool_result(raw_result)
                _safe(safe_result)
                _require(raw_result["owners"][0]["owner"] == RAW_PERSON)
                _require(
                    safe_result
                    == {"owners": [tokens], tokens["owner"]: [tokens["account"], "", None]}
                )
                llm_seen.append(safe_result)
            _require(session.sanitize("Mr Lovelace") == tokens["owner"])
            uncertain = session.sanitize(f"{RAW_NAMES[0]} met {RAW_NAMES[1]}. Ask {RAW_NAMES[2]}.")
            _safe(uncertain)
            _require(len(set(re.findall(r"\[PERSON_[0-9a-f]{32}_[1-9][0-9]*\]", uncertain))) == 3)
            before = session.transcript
            try:
                session.rehydrate_for_tool(ToolCall(name="blocked", arguments=tokens))
            except DataReleaseDenied as error:
                _safe(str(error))
                _require(error.__cause__ is error.__context__ is None)
            else:
                _require(False)
            with TrustSession(detector=detector) as other:
                try:
                    other.rehydrate_for_tool(ToolCall(name="get_account", arguments=tokens))
                except CrossSessionTokenError as error:
                    _safe(str(error))
                else:
                    _require(False)
            with TrustSession(detector=detector) as unconfigured:
                denied_token = unconfigured.sanitize(RAW_ACCOUNT)
                try:
                    unconfigured.rehydrate_for_tool(
                        ToolCall(name="get_account", arguments={"account": denied_token})
                    )
                except DataReleaseDenied as error:
                    _safe(str(error))
                else:
                    _require(False)
            _require(session.transcript == before)
            transcript = [entry.model_dump(mode="json") for entry in session.transcript]
            _safe(transcript)
            _safe(llm_seen)
        _require(session.is_closed)
        try:
            session.rehydrate_for_tool(ToolCall(name="get_account", arguments=tokens))
        except SessionClosedError as error:
            _safe(str(error))
        else:
            _require(False)
        audit = [event.model_dump(mode="json") for event in gate.audit_sink.events]
        _safe(audit)
        _require(not attempts)
    return {
        "python": sys.version.split()[0],
        "trustgate": importlib.metadata.version("trustgate"),
        "spacy": importlib.metadata.version("spacy"),
        "pydantic": importlib.metadata.version("pydantic"),
        "import_origin": str(origin),
        "isolated_install": True,
        "typed_package": True,
        "read_and_write_flow": True,
        "safe_llm_values_and_diagnostics": True,
        "stable_and_ambiguous_identity": True,
        "default_deny_and_replay_rejection": True,
        "closed_session_rejected": True,
        "runtime_network_attempts": len(attempts),
        "missing_model_fails_closed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        report = run(arguments.model_path.resolve())
    except Exception:
        print("Release smoke validation failed.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
