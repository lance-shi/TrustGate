"""Executable example: real local detection, mocked boundaries, and safe output."""

import importlib.util
import json
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import DetectionUnavailableError, SessionClosedError, ToolCall, TrustGate

DEMO_PATH = Path(__file__).resolve().parents[1] / "examples" / "boundary_demo.py"


@pytest.fixture
def demo():
    spec = importlib.util.spec_from_file_location("boundary_demo", DEMO_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assert_safe(value):
    assert_no_raw_sensitive_values(
        value,
        "Ada",
        "Lovelace",
        "12345678",
        "Joanna",
        "Joseph",
        "Taylor",
        "ada lovelace",
        "joanna taylor",
        "joseph taylor",
        "jo taylor",
    )


def _assert_plain_json(value):
    # LLM payloads must contain only data, never a session, vault or callable.
    if type(value) is dict:
        assert all(type(key) is str for key in value)
        for item in value.values():
            _assert_plain_json(item)
    elif type(value) is list:
        for item in value:
            _assert_plain_json(item)
    else:
        assert value is None or type(value) in (str, bool, int, float)


def _assert_report(report):
    _assert_plain_json(report)
    for key in (
        "stable_person_token",
        "denied_release",
        "cross_session_rejected",
        "session_closed",
        "closed_session_rejected",
    ):
        assert report[key] is True
    calls = report["llm_tool_calls"]
    assert report["llm_replies"] == ["The tool returned tokenized account data."] * 2
    assert [call["name"] for call in calls] == ["get_account", "update_account"]
    owner = calls[0]["arguments"]["owner"]
    account = calls[0]["arguments"]["account"]
    assert calls[0]["arguments"] == calls[1]["arguments"]
    assert re.fullmatch(r"\[PERSON_[1-9][0-9]*\]", owner)
    assert re.fullmatch(r"\[ACCOUNT_NUMBER_[1-9][0-9]*\]", account)
    assert report["llm_input"] == f"{owner} has account {account}."
    assert report["followup"] == owner
    assert report["ambiguity"]["state"] == "ambiguous"
    tokens = re.findall(r"\[PERSON_[1-9][0-9]*\]", report["ambiguity"]["text"])
    assert len(tokens) == len(set(tokens)) == 3
    assert report["ambiguity"]["token"] == tokens[-1]
    assert owner not in tokens
    for destination, status in (
        ("get_account", "read_complete"),
        ("update_account", "update_complete"),
    ):
        assert report["llm_tool_results"][destination] == {
            "status": status,
            "owners": [{"name": owner, "account": account}],
            owner: [owner, account],
            "empty": ["", {}, [], None],
        }
    transcript = report["transcript"]
    assert [entry["kind"] for entry in transcript] == [
        "input_sanitized",
        "tool_result_sanitized",
        "tool_result_sanitized",
        "input_sanitized",
        "input_sanitized",
        "input_sanitized",
    ]
    assert transcript[0]["content"] == report["llm_input"]
    assert transcript[1]["content"] == report["llm_tool_results"]["get_account"]
    assert transcript[2]["content"] == report["llm_tool_results"]["update_account"]
    assert transcript[-1]["content"] == tokens[-1]
    assert set(report["audit_summary"]["resolution_states"]) == {
        "exact",
        "unique_partial",
        "ambiguous",
    }
    assert {"tool_release_allowed", "tool_release_denied", "session_closed"} <= set(
        report["audit_summary"]["event_types"]
    )
    _assert_safe(report)


def test_real_demo_only_sends_sanitized_values_to_mock_llm_and_prints_safe_report(
    demo, monkeypatch, capsys, caplog
):
    llm = demo.mock_llm
    tool = demo.mock_tool
    reply = demo.mock_llm_reply
    llm_inputs = []
    llm_results = []
    tool_destinations = []

    def checked_llm(safe_input, destination):
        _assert_plain_json(safe_input)
        _assert_safe(safe_input)
        llm_inputs.append(safe_input)
        return llm(safe_input, destination)

    def checked_tool(destination, arguments):
        assert arguments == {"owner": "Ada Lovelace", "account": "12345678"}
        tool_destinations.append(destination)
        return tool(destination, arguments)

    def checked_reply(safe_result):
        _assert_plain_json(safe_result)
        _assert_safe(safe_result)
        llm_results.append(safe_result)
        return reply(safe_result)

    monkeypatch.setattr(demo, "mock_llm", checked_llm)
    monkeypatch.setattr(demo, "mock_tool", checked_tool)
    monkeypatch.setattr(demo, "mock_llm_reply", checked_reply)
    assert demo.main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    _assert_report(report)
    assert llm_inputs == [report["llm_input"]] * 2
    # The denied destination never reaches the mock tool.
    assert tool_destinations == ["get_account", "update_account"]
    assert llm_results == [report["llm_tool_results"][name] for name in tool_destinations]
    _assert_safe((captured.out, captured.err, caplog.text))


def test_demo_runs_offline_with_local_model(demo, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("The demo attempted a network connection.")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    _assert_report(demo.run_demo())


def test_demo_does_not_assume_token_sequence_starts_at_one(demo):
    first = demo.run_demo()
    second = demo.run_demo()
    _assert_report(first)
    _assert_report(second)
    assert first["followup"] != second["followup"]


def test_script_runs_from_another_working_directory(tmp_path):
    completed = subprocess.run(
        [sys.executable, str(DEMO_PATH)],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    _assert_safe((completed.stdout, completed.stderr))
    assert completed.returncode == 0
    assert completed.stderr == ""
    _assert_report(json.loads(completed.stdout))


@pytest.mark.parametrize("source", ["model", "tool", "missed_detection"])
def test_cli_failures_emit_only_fixed_message_and_close_sessions(demo, monkeypatch, capsys, source):
    gate = TrustGate.from_yaml(demo.POLICY_PATH)
    create = gate.session
    sessions = []

    def tracked_session(**kwargs):
        session = create(**kwargs)
        sessions.append(session)
        return session

    monkeypatch.setattr(gate, "session", tracked_session)
    monkeypatch.setattr(demo.TrustGate, "from_yaml", lambda path: gate)

    def fail(*args, **kwargs):
        raise RuntimeError("Ada Lovelace has account 12345678.")

    if source == "tool":
        monkeypatch.setattr(demo, "mock_tool", fail)
    elif source == "model":

        def no_model(self, text):
            raise DetectionUnavailableError

        monkeypatch.setattr("trustgate.session.PresidioDetector.detect", no_model)
    else:
        # Simulate NER missing these fixtures: the demo must not print the result.
        monkeypatch.setattr("trustgate.session.PresidioDetector.detect", lambda self, text: ())
    assert demo.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Demo failed. Check the local model, policy, and demo tests.\n"
    assert sessions and all(session.is_closed for session in sessions)
    for session in sessions:
        with pytest.raises(SessionClosedError):
            session.rehydrate_for_tool(ToolCall(name="get_account"))
    _assert_safe((captured.out, captured.err))


def test_bad_policy_emits_no_path_or_traceback(demo, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(demo, "POLICY_PATH", tmp_path / "Ada-Lovelace-12345678.yaml")
    assert demo.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.err
    _assert_safe(captured.err)
