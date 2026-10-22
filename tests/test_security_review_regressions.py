"""Regression tests for overlap, dependency logging, and restart isolation."""

import json
import logging
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from io import StringIO

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import DetectionUnavailableError, MalformedTokenError, TrustPolicy, TrustSession
from trustgate.detection import PresidioDetector
from trustgate.vault import TokenVault


@pytest.mark.parametrize("boundary", ["input", "result"])
def test_real_cross_type_overlap_never_becomes_a_releasable_token(boundary, caplog):
    raw = "12345678@example.com"
    policy = TrustPolicy(
        version=1,
        data_policies={
            "ACCOUNT_NUMBER": {"external_llm": "tokenize", "destinations": {"send_email": "deny"}},
            "EMAIL_ADDRESS": {"external_llm": "tokenize", "destinations": {"send_email": "allow"}},
        },
    )
    detector = PresidioDetector()
    assert {entity.entity_type for entity in detector.detect(raw)} >= {
        "ACCOUNT_NUMBER",
        "EMAIL_ADDRESS",
    }
    with TrustSession(detector=detector, policy=policy, transcript=True) as session:
        with pytest.raises(DetectionUnavailableError) as error:
            if boundary == "input":
                session.sanitize(raw)
            else:
                session.sanitize_tool_result({raw: [raw]})
        assert session.transcript == ()
        assert session._vault._entries_by_token == {}
        assert_no_raw_sensitive_values(
            (error.value, session._audit_sink.events, caplog.text), raw, "12345678"
        )


@pytest.mark.parametrize("boundary", ["input", "result"])
def test_real_detector_debug_logs_do_not_contain_context(boundary, caplog):
    caplog.set_level(logging.DEBUG)
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("presidio-analyzer")
    logger.addHandler(handler)
    try:
        with TrustSession(detector=PresidioDetector(), transcript=True) as session:
            raw = "Ada Lovelace phone +1 212-555-0123 has account 12345678."
            safe = (
                session.sanitize(raw)
                if boundary == "input"
                else session.sanitize_tool_result({"value": raw})
            )
            assert_no_raw_sensitive_values(
                (
                    safe,
                    session.transcript,
                    session._audit_sink.events,
                    caplog.text,
                    stream.getvalue(),
                ),
                "Ada Lovelace",
                "ada lovelace",
                "12345678",
                "212-555-0123",
            )
            # A random hex namespace/hash can coincidentally contain "ada".
            # Match normalized name words in logs, not substrings in opaque IDs.
            assert re.search(r"\b(?:ada|lovelace)\b", caplog.text + stream.getvalue(), re.I) is None
        logger.debug("host logging still works")
        assert "host logging still works" in stream.getvalue()
    finally:
        logger.removeHandler(handler)


@pytest.mark.parametrize("logger_name", ["presidio-analyzer", "decision_process"])
def test_dependency_log_suppression_is_context_local_and_restored_after_failure(
    caplog, logger_name, monkeypatch
):
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger=logger_name)
    logger = logging.getLogger(logger_name)
    monkeypatch.setattr(logger, "propagate", True)
    original_level = logger.level

    class Analyzer:
        def analyze(self, **kwargs):
            logger.error("Sensitive context: %s", kwargs["text"])
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(logger.debug, "unrelated concurrent host record").result()
            raise RuntimeError(kwargs["text"])

    detector = object.__new__(PresidioDetector)
    detector._analyzer = Analyzer()
    with pytest.raises(DetectionUnavailableError) as error:
        detector.detect("RAW_DEBUG_CONTEXT_DO_NOT_LEAK")
    logger.debug("after failure")
    assert logger.level == original_level
    assert "unrelated concurrent host record" in caplog.text
    assert "after failure" in caplog.text
    assert_no_raw_sensitive_values((error.value, caplog.text), "RAW_DEBUG_CONTEXT_DO_NOT_LEAK")


def test_detector_initialization_logs_cannot_disclose_configuration(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)

    def failing_provider(**kwargs):
        logging.getLogger("presidio-analyzer").error("RAW_MODEL_CONTEXT_DO_NOT_LEAK")
        raise RuntimeError("RAW_MODEL_CONTEXT_DO_NOT_LEAK")

    monkeypatch.setattr("trustgate.detection.NlpEngineProvider", failing_provider)
    with pytest.raises(DetectionUnavailableError) as error:
        PresidioDetector()
    assert_no_raw_sensitive_values((error.value, caplog.text), "RAW_MODEL_CONTEXT_DO_NOT_LEAK")


@pytest.mark.parametrize(
    "token",
    [
        "[ACCOUNT_NUMBER_1]",
        "[ACCOUNT_NUMBER_" + "0" * 31 + "_1]",
        "[ACCOUNT_NUMBER_" + "0" * 33 + "_1]",
        "[ACCOUNT_NUMBER_" + "A" * 32 + "_1]",
        "[ACCOUNT_NUMBER_" + "0" * 32 + "_0]",
        "[ACCOUNT_NUMBER_" + "0" * 32 + "_01]",
    ],
)
def test_legacy_or_malformed_namespaces_are_rejected(token):
    with pytest.raises(MalformedTokenError):
        TokenVault().resolve(token)


def test_namespace_is_random_even_when_private_vault_owner_id_is_reused():
    first = TokenVault(session_id="same_owner")
    second = TokenVault(session_id="same_owner")
    a = first.store(value="11112222", entity_type="ACCOUNT_NUMBER")
    b = second.store(value="33334444", entity_type="ACCOUNT_NUMBER")
    assert a.value != b.value


@pytest.mark.parametrize("destination", ["read_value", "write_value"])
def test_old_token_cannot_resolve_to_a_new_process_value(destination):
    script = """
import json, sys
from trustgate import ToolCall, TrustSession, TrustPolicy, TokenResolutionError
from trustgate.models import SensitiveEntity
class Detector:
    def detect(self, text):
        return (SensitiveEntity(entity_type="ACCOUNT_NUMBER", start=0, end=len(text), score=1),)
policy = TrustPolicy(version=1, data_policies={"ACCOUNT_NUMBER": {
    "external_llm": "tokenize", "destinations": {"read_value": "allow", "write_value": "allow"}}})
with TrustSession(detector=Detector(), policy=policy) as session:
    token = session.sanitize(sys.argv[1])
    call = ToolCall(name=sys.argv[3], arguments={"value": token})
    assert session.rehydrate_for_tool(call) == {"value": sys.argv[1]}
    rejected = True
    if sys.argv[2]:
        try:
            call = ToolCall(name=sys.argv[3], arguments={sys.argv[2]: [sys.argv[2]]})
            session.rehydrate_for_tool(call)
        except TokenResolutionError:
            pass
        else:
            rejected = False
    print(json.dumps({"token": token, "rejected": rejected}))
"""

    def run(raw, old):
        result = subprocess.run(
            [sys.executable, "-c", script, raw, old, destination],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
        )
        assert_no_raw_sensitive_values((result.stdout, result.stderr), "11112222", "33334444")
        return json.loads(result.stdout)

    first = run("11112222", "")
    second = run("33334444", first["token"])
    assert first["token"] != second["token"]
    assert second["rejected"]
