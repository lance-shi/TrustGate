"""Tests for conservative, session-local exact person-name resolution."""

from dataclasses import dataclass
from re import fullmatch

from security_assertions import assert_no_raw_sensitive_values

from trustgate import InMemoryAuditSink, SensitiveEntity, ToolCall, TrustGate, TrustPolicy


@dataclass(frozen=True)
class StaticDetector:
    entities: tuple[SensitiveEntity, ...]

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        return self.entities


@dataclass(frozen=True)
class MappingDetector:
    entities_by_text: dict[str, tuple[SensitiveEntity, ...]]

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        return self.entities_by_text.get(text, ())


def _person(start: int, end: int) -> SensitiveEntity:
    return SensitiveEntity(entity_type="PERSON", start=start, end=end, score=0.9)


def _person_gate(*, audit_sink: InMemoryAuditSink | None = None) -> TrustGate:
    return TrustGate(
        audit_sink=audit_sink,
        policy=TrustPolicy(
            version=1,
            data_policies={
                "PERSON": {
                    "external_llm": "tokenize",
                    "destinations": {"lookup_person": "allow"},
                }
            },
        ),
    )


def test_exact_normalized_full_names_reuse_one_llm_visible_token() -> None:
    first_name = "Ada Lovelace"
    second_name = "MR. ADA LOVELACE"
    text = f"{first_name} met {second_name}."
    session = _person_gate().session()
    session._detector = StaticDetector(
        (
            _person(0, len(first_name)),
            _person(len(first_name) + 5, len(text) - 1),
        )
    )

    sanitized = session.sanitize(text)

    assert fullmatch(r"\[PERSON_([1-9][0-9]*)\] met \[PERSON_\1\]\.", sanitized)
    assert_no_raw_sensitive_values(sanitized, first_name, second_name)


def test_exact_resolution_rehydrates_the_first_canonical_value_only_for_the_tool() -> None:
    canonical_value = "Ada Lovelace"
    equivalent_mention = "ADA LOVELACE"
    session = _person_gate().session()
    session._detector = StaticDetector((_person(0, len(canonical_value)),))
    token = session.sanitize(canonical_value)
    session._detector = StaticDetector((_person(0, len(equivalent_mention)),))

    assert session.sanitize(equivalent_mention) == token
    assert session.rehydrate_for_tool(
        ToolCall(name="lookup_person", arguments={"person": token})
    ) == {"person": canonical_value}


def test_tool_results_share_the_entity_token_and_audit_no_raw_values() -> None:
    canonical_value = "Ada Lovelace"
    equivalent_mention = "MR. ADA LOVELACE"
    audit_sink = InMemoryAuditSink()
    session = _person_gate(audit_sink=audit_sink).session()
    session._detector = MappingDetector(
        {
            canonical_value: (_person(0, len(canonical_value)),),
            equivalent_mention: (_person(0, len(equivalent_mention)),),
        }
    )

    first_result = session.sanitize_tool_result({"owner": canonical_value})
    second_result = session.sanitize_tool_result({"owner": equivalent_mention})
    token = first_result["owner"]

    assert token == second_result["owner"]
    assert session.rehydrate_for_tool(
        ToolCall(name="lookup_person", arguments={"person": token})
    ) == {"person": canonical_value}
    assert_no_raw_sensitive_values(audit_sink.events, canonical_value, equivalent_mention)


def test_single_component_names_do_not_merge_on_casefolding() -> None:
    first_name = "Ada"
    second_name = "ADA"
    text = f"{first_name} met {second_name}."
    session = _person_gate().session()
    session._detector = StaticDetector(
        (
            _person(0, len(first_name)),
            _person(len(first_name) + 5, len(text) - 1),
        )
    )

    sanitized = session.sanitize(text)

    match = fullmatch(r"\[PERSON_([1-9][0-9]*)\] met \[PERSON_([1-9][0-9]*)\]\.", sanitized)
    assert match is not None
    assert match.group(1) != match.group(2)


def test_different_normalized_full_names_remain_distinct_and_audit_stays_safe() -> None:
    first_name = "Ada Lovelace"
    second_name = "Ada Byron"
    text = f"{first_name} met {second_name}."
    audit_sink = InMemoryAuditSink()
    session = _person_gate(audit_sink=audit_sink).session()
    session._detector = StaticDetector(
        (
            _person(0, len(first_name)),
            _person(len(first_name) + 5, len(text) - 1),
        )
    )

    sanitized = session.sanitize(text)

    match = fullmatch(r"\[PERSON_([1-9][0-9]*)\] met \[PERSON_([1-9][0-9]*)\]\.", sanitized)
    assert match is not None
    assert match.group(1) != match.group(2)
    assert_no_raw_sensitive_values(audit_sink.events, first_name, second_name)
