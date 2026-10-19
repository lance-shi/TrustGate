"""Custom aliases are validated, copied, ephemeral, and isolated per session."""

import json
from collections import UserDict
from collections.abc import Sequence
from dataclasses import dataclass

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AliasValidationError,
    CrossSessionTokenError,
    DataReleaseDenied,
    InMemoryAuditSink,
    SensitiveEntity,
    SessionClosedError,
    ToolCall,
    TrustGate,
    TrustPolicy,
    TrustSession,
)
from trustgate.entity import EntityResolutionState as State


@dataclass(frozen=True)
class NameDetector:
    names: tuple[str, ...]

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        if text not in self.names:
            return ()
        return (SensitiveEntity(entity_type="PERSON", start=0, end=len(text), score=0.9),)


def _gate() -> TrustGate:
    return TrustGate(
        audit_sink=InMemoryAuditSink(),
        policy=TrustPolicy(
            version=1,
            data_policies={
                "PERSON": {
                    "external_llm": "tokenize",
                    "destinations": {"lookup_person": "allow", "update_person": "allow"},
                }
            },
        ),
    )


def _rehydrate(session: TrustSession, token: str, destination: str = "lookup_person") -> str:
    result = session.rehydrate_for_tool(ToolCall(name=destination, arguments={"person": token}))
    assert isinstance(result["person"], str)
    return result["person"]


@pytest.mark.parametrize("entry", ["gate", "session"])
@pytest.mark.parametrize("destination", ["lookup_person", "update_person"])
def test_public_session_alias_configuration_resolves_to_the_canonical_value(
    entry, destination
) -> None:
    aliases = {"Liz": ["Elizabeth"]}
    gate = _gate()
    session = (
        gate.session(aliases=aliases)
        if entry == "gate"
        else TrustSession(aliases=aliases, policy=gate.policy)
    )
    session._detector = NameDetector(("Elizabeth Taylor", "Liz Taylor"))
    canonical = session.sanitize("Elizabeth Taylor")
    assert session.sanitize("Liz Taylor") == canonical
    assert _rehydrate(session, canonical, destination) == "Elizabeth Taylor"
    assert session._entity_resolver._mention_states[-1].state is State.UNIQUE_ALIAS
    assert aliases == {"Liz": ["Elizabeth"]}


def test_alias_snapshot_does_not_follow_caller_dictionary_or_list_mutations() -> None:
    targets = ["Elizabeth"]
    aliases = {"Liz": targets}
    session = _gate().session(aliases=aliases)
    targets[:] = ["Eliza"]
    aliases.clear()
    aliases["Beth"] = ["Elizabeth"]
    session._detector = NameDetector(
        ("Elizabeth Taylor", "Eliza Taylor", "Liz Taylor", "Beth Taylor")
    )
    canonical = session.sanitize("Elizabeth Taylor")
    session.sanitize("Eliza Taylor")
    assert session.sanitize("Liz Taylor") == canonical
    assert session.sanitize("Beth Taylor") != canonical


def test_alias_configuration_is_not_shared_by_sessions_of_the_same_gate() -> None:
    gate = _gate()
    custom = gate.session(aliases={"Liz": ["Elizabeth"]})
    default = gate.session()
    for session in (custom, default):
        session._detector = NameDetector(("Elizabeth Taylor", "Liz Taylor"))
    canonical = custom.sanitize("Elizabeth Taylor")
    assert custom.sanitize("Liz Taylor") == canonical
    default_canonical = default.sanitize("Elizabeth Taylor")
    assert default.sanitize("Liz Taylor") != default_canonical
    with pytest.raises(CrossSessionTokenError):
        _rehydrate(default, canonical)
    assert not hasattr(gate, "_aliases")


def test_two_sessions_can_use_different_relations_for_the_same_alias() -> None:
    gate = _gate()
    for target in ("Elizabeth", "Eliza"):
        session = gate.session(aliases={"Liz": [target]})
        session._detector = NameDetector(("Elizabeth Taylor", "Eliza Taylor", "Liz Taylor"))
        tokens = {name: session.sanitize(name) for name in ("Elizabeth Taylor", "Eliza Taylor")}
        assert session.sanitize("Liz Taylor") == tokens[f"{target} Taylor"]


@pytest.mark.parametrize(
    "aliases",
    [{" ＬＩＺ ": (" ELIZABETH ",)}, UserDict({"Liz": ["Elizabeth"]})],
)
def test_aliases_accept_mapping_and_sequence_inputs_and_normalize_names(aliases) -> None:
    session = _gate().session(aliases=aliases)
    session._detector = NameDetector(("Elizabeth Taylor", "Liz Taylor"))
    canonical = session.sanitize("Elizabeth Taylor")
    assert session.sanitize("Liz Taylor") == canonical


def test_normalized_duplicate_alias_keys_union_their_candidates() -> None:
    session = _gate().session(aliases={"Liz": ["Elizabeth"], "ＬＩＺ": ["Eliza"]})
    session._detector = NameDetector(("Elizabeth Taylor", "Eliza Taylor", "Liz Taylor"))
    first, second = session.sanitize("Elizabeth Taylor"), session.sanitize("Eliza Taylor")
    alias = session.sanitize("Liz Taylor")
    assert alias not in (first, second)
    assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS
    assert session.sanitize("Liz Taylor") == alias


def test_additions_do_not_replace_builtin_candidates() -> None:
    session = _gate().session(aliases={"Jo": ["Jocelyn"]})
    session._detector = NameDetector(("Joanna Taylor", "Jocelyn Taylor", "Jo Taylor"))
    first, second = session.sanitize("Joanna Taylor"), session.sanitize("Jocelyn Taylor")
    alias = session.sanitize("Jo Taylor")
    assert alias not in (first, second)
    assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS


def test_custom_aliases_do_not_expand_in_reverse_or_through_chains() -> None:
    session = _gate().session(aliases={"Liz": ["Beth"], "Beth": ["Elizabeth"]})
    session._detector = NameDetector(("Elizabeth Taylor", "Liz Taylor", "Beth Taylor"))
    canonical = session.sanitize("Elizabeth Taylor")
    assert session.sanitize("Beth Taylor") == canonical
    assert session.sanitize("Liz Taylor") != canonical


def test_custom_aliases_do_not_retroactively_promote_unresolved_mentions() -> None:
    session = _gate().session(aliases={"Liz": ["Elizabeth"]})
    session._detector = NameDetector(("Liz", "Elizabeth Taylor"))
    earlier = session.sanitize("Liz")
    full = session.sanitize("Elizabeth Taylor")
    assert session.sanitize("Liz") == earlier != full
    assert _rehydrate(session, earlier) == "Liz"
    assert session._entity_resolver._mention_states[-1].state is State.UNRESOLVED


def test_custom_aliases_still_require_explicit_destination_allow() -> None:
    session = TrustSession(aliases={"Liz": ["Elizabeth"]})
    session._detector = NameDetector(("Elizabeth Taylor", "Liz Taylor"))
    session.sanitize("Elizabeth Taylor")
    token = session.sanitize("Liz Taylor")
    with pytest.raises(DataReleaseDenied) as error:
        _rehydrate(session, token)
    assert_no_raw_sensitive_values(error.value, "Liz", "Elizabeth")


def test_close_clears_custom_aliases_even_through_a_retained_producer_reference() -> None:
    aliases = {"Liz": ["Elizabeth"]}
    session = _gate().session(aliases=aliases)
    producer = session._entity_resolver._alias_resolver
    assert ("liz", "elizabeth") in producer._aliases
    session.close()
    session.close()
    assert producer._aliases == frozenset()
    assert aliases == {"Liz": ["Elizabeth"]}
    with pytest.raises(SessionClosedError):
        session.sanitize("Liz Taylor")


def test_custom_aliases_never_appear_in_results_audits_or_logs(caplog) -> None:
    # Avoid an alias that is a substring of fixed audit vocabulary ("normalized").
    gate = _gate()
    session = gate.session(aliases={"Beth": ["Elizabeth"]})
    session._detector = NameDetector(("Elizabeth Taylor", "Beth Taylor"))
    token = session.sanitize("Elizabeth Taylor")
    result = {"owner": ["Beth Taylor"]}
    safe = session.sanitize_tool_result(result)
    assert safe == {"owner": [token]}
    assert result == {"owner": ["Beth Taylor"]}
    _rehydrate(session, token)
    session.close()
    assert_no_raw_sensitive_values(
        (
            safe,
            gate.audit_sink.events,
            json.dumps([event.model_dump(mode="json") for event in gate.audit_sink.events]),
            repr(session),
            repr(session._entity_resolver),
            caplog.text,
        ),
        "Beth",
        "Elizabeth",
        "beth",
        "elizabeth",
    )


@pytest.mark.parametrize("entry", ["gate", "session"])
@pytest.mark.parametrize(
    "aliases",
    [
        "RAW_ALIAS_SECRET",
        ["Liz", "Elizabeth"],
        {"Liz": "RAW_ALIAS_SECRET"},
        {"Liz": b"RAW_ALIAS_SECRET"},
        {"Liz": None},
        {"Liz": []},
        {"Liz": {"Elizabeth"}},
        {"Liz": [123]},
        {123: ["Elizabeth"]},
        {"": ["Elizabeth"]},
        {"Liz": [""]},
        {"Mr Liz": ["Elizabeth"]},
        {"Liz": ["Elizabeth Taylor"]},
        {"Mr.": ["Elizabeth"]},
        {"Liz": ["[PERSON_1]"]},
        {"123": ["Elizabeth"]},
        {"AcceptedNickname": ["Elizabeth"], "RAW_ALIAS_SECRET": [None]},
    ],
    ids=[f"malformed-{index}" for index in range(17)],
)
def test_malformed_configuration_fails_without_raw_exception_context(
    entry, aliases, caplog
) -> None:
    gate = _gate()
    with pytest.raises(AliasValidationError) as error:
        if entry == "gate":
            gate.session(aliases=aliases)
        else:
            TrustSession(aliases=aliases, audit_sink=gate.audit_sink)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert gate.audit_sink.events == ()
    assert_no_raw_sensitive_values(
        (error.value, caplog.text),
        "RAW_ALIAS_SECRET",
        "Liz",
        "Elizabeth",
        "AcceptedNickname",
    )


def test_mapping_and_sequence_read_errors_cannot_leak_exception_chains() -> None:
    class BrokenMapping(UserDict):
        def items(self):
            raise ValueError("RAW_ALIAS_SECRET")

    class BrokenSequence(Sequence):
        def __len__(self):
            return 1

        def __getitem__(self, index):
            raise ValueError("RAW_ALIAS_SECRET")

    for aliases in (BrokenMapping(), {"Liz": BrokenSequence()}):
        with pytest.raises(AliasValidationError) as error:
            _gate().session(aliases=aliases)
        assert error.value.__context__ is error.value.__cause__ is None
        assert_no_raw_sensitive_values(error.value, "RAW_ALIAS_SECRET", "Liz")


@pytest.mark.parametrize("aliases", [None, {}])
def test_omitted_or_empty_aliases_preserve_builtins(aliases) -> None:
    session = _gate().session(aliases=aliases)
    session._detector = NameDetector(("Joanna Taylor", "Jo Taylor"))
    token = session.sanitize("Joanna Taylor")
    assert session.sanitize("Jo Taylor") == token


def test_duplicate_alias_targets_do_not_make_one_identity_ambiguous() -> None:
    session = _gate().session(aliases={"Liz": ["Elizabeth", "ELIZABETH"], "Beth": ["Elizabeth"]})
    session._detector = NameDetector(("Elizabeth Taylor", "Liz Taylor", "Beth Taylor"))
    token = session.sanitize("Elizabeth Taylor")
    assert session.sanitize("Liz Taylor") == session.sanitize("Beth Taylor") == token
    assert all(
        item.state is State.UNIQUE_ALIAS for item in session._entity_resolver._mention_states[1:]
    )


def test_custom_alias_uses_remaining_components_to_disambiguate() -> None:
    session = _gate().session(aliases={"Liz": ["Elizabeth", "Eliza"]})
    session._detector = NameDetector(("Elizabeth Taylor", "Eliza Jones", "Liz Taylor", "Liz"))
    first = session.sanitize("Elizabeth Taylor")
    second = session.sanitize("Eliza Jones")
    assert session.sanitize("Liz Taylor") == first
    assert session.sanitize("Liz") not in (first, second)
    assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS


@pytest.mark.parametrize(
    ("alias", "target"),
    [("Mary-Jane", "Maryjane"), ("O'Neil", "Oneil"), ("O’Neil", "Oneil"), ("Jose\u0301", "Joseph")],
)
def test_custom_alias_normalization_retains_supported_name_punctuation(alias, target) -> None:
    session = _gate().session(aliases={alias: [target]})
    full, mention = f"{target} Taylor", f"{alias} Taylor"
    session._detector = NameDetector((full, mention))
    token = session.sanitize(full)
    assert session.sanitize(mention) == token
