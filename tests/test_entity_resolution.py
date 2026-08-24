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
