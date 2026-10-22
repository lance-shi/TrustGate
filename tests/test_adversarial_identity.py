"""Combined identity attacks through the public sensitive-data boundaries."""

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass
from itertools import permutations
from unicodedata import normalize

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    CrossSessionTokenError,
    DataReleaseDenied,
    InMemoryAuditSink,
    SensitiveEntity,
    SessionClosedError,
    ToolCall,
    TrustGate,
    TrustPolicy,
    TrustSession,
    UnknownTokenError,
)
from trustgate import (
    EntityResolutionState as State,
)
from trustgate.models import JsonValue

KNOWN = ("Jo Smith", "Joanna Taylor", "Joseph Taylor")
MENTIONS = ("Jo", "Jo Taylor", "Mr Taylor", "Mr Smith", "Joanna", "JOANNA TAYLOR")


@dataclass(frozen=True)
class NameDetector:
    names: frozenset[str]

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        entities: list[SensitiveEntity] = []
        offset = 0
        for part in text.split(" | "):
            if part in self.names:
                entities.append(
                    SensitiveEntity(
                        entity_type="PERSON", start=offset, end=offset + len(part), score=1
                    )
                )
            offset += len(part) + 3
        # Detection order must never decide identity observation order.
        return tuple(reversed(entities))


def _policy(decision: str = "allow") -> TrustPolicy | None:
    if decision == "missing":
        return None
    return TrustPolicy(
        version=1,
        data_policies={
            "PERSON": {
                "external_llm": "tokenize",
                "destinations": {"lookup_person": decision, "update_person": decision},
            }
        },
    )


@contextmanager
def _session(
    names: Sequence[str],
    *,
    aliases: Mapping[str, Sequence[str]] | None = None,
    transcript: bool = True,
    decision: str = "allow",
) -> Iterator[TrustSession]:
    with TrustSession(
        detector=NameDetector(frozenset(names)),
        policy=_policy(decision),
        audit_sink=InMemoryAuditSink(),
        aliases=aliases,
        transcript=transcript,
    ) as session:
        yield session


def _release(session: TrustSession, token: str, destination: str = "lookup_person") -> str:
    value = session.rehydrate_for_tool(ToolCall(name=destination, arguments={"person": token}))[
        "person"
    ]
    assert isinstance(value, str)
    return value


def _assert_safe(session, names, caplog, capsys, *outputs):
    captured = capsys.readouterr()
    assert_no_raw_sensitive_values(
        (
            outputs,
            [event.model_dump_json() for event in session._audit_sink.events],
            session.transcript,
            [asdict(item) for item in session._entity_resolver._mention_states],
            caplog.text,
            captured.out,
            captured.err,
        ),
        *names,
        *(normalize("NFKC", name).casefold() for name in names),
    )


@pytest.mark.parametrize("order", list(permutations(KNOWN)))
@pytest.mark.parametrize("channel", ["input", "tool_result"])
@pytest.mark.parametrize("transcript", [False, True])
def test_complete_candidate_union_is_independent_of_registration_order_and_channel(
    order, channel, transcript, caplog, capsys
):
    names = KNOWN + MENTIONS
    with _session(names, transcript=transcript) as session:
        if channel == "input":
            tokens = dict(zip(order, session.sanitize(" | ".join(order)).split(" | "), strict=True))
        else:
            raw = {"people": [{"name": name} for name in order]}
            before = deepcopy(raw)
            safe = session.sanitize_tool_result(raw)
            assert raw == before
            tokens = {name: item["name"] for name, item in zip(order, safe["people"], strict=True)}
        assert len(set(tokens.values())) == 3
        history = tuple(session._entity_resolver._mention_states)
        raw = {"followups": [[mention] for mention in MENTIONS], "Mr Taylor": {"name": "Jo Taylor"}}
        before = deepcopy(raw)
        safe = session.sanitize_tool_result(raw)
        assert raw == before
        observed = [item[0] for item in safe["followups"]]
        assert len(set(observed[:3])) == 3
        assert not set(observed[:3]) & set(tokens.values())
        assert observed[3:] == [
            tokens["Jo Smith"],
            tokens["Joanna Taylor"],
            tokens["Joanna Taylor"],
        ]
        assert safe[observed[2]] == {"name": observed[1]}
        assert tuple(session._entity_resolver._mention_states[:3]) == history
        states = session._entity_resolver._mention_states[3:9]
        assert [item.state for item in states] == [
            State.AMBIGUOUS,
            State.AMBIGUOUS,
            State.AMBIGUOUS,
            State.UNIQUE_PARTIAL,
            State.UNIQUE_PARTIAL,
            State.EXACT,
        ]
        for name, token in tokens.items():
            assert _release(session, token, "update_person") == name
        for mention, token in zip(MENTIONS[:3], observed[:3], strict=True):
            assert _release(session, token) == mention
            assert session.sanitize(mention) == token
        _assert_safe(session, names, caplog, capsys, safe, tuple(tokens.values()))


@pytest.mark.parametrize("order", list(permutations(KNOWN)))
@pytest.mark.parametrize("early", ["Jo", "Mr Taylor"])
def test_early_uncertainty_survives_later_complete_conflicting_candidate_sets(
    order, early, caplog, capsys
):
    names = KNOWN + MENTIONS
    with _session(names) as session:
        token = session.sanitize(early)
        original = session._entity_resolver._mention_states[0]
        audit = session._audit_sink.events[-1].model_dump_json()
        for name in order:
            session.sanitize_tool_result({"people": [name, {"earlier": early}]})
        assert session.sanitize(early) == token
        assert _release(session, token) == early
        assert session._entity_resolver._mention_states[0] is original
        assert original.state is State.UNRESOLVED
        assert session._entity_resolver._mention_states[-1].state is State.UNRESOLVED
        assert session._audit_sink.events[1].model_dump_json() == audit
        assert len(session._entity_resolver._identities_by_id) == 3
        _assert_safe(session, names, caplog, capsys, token)


@pytest.mark.parametrize("decision", ["allow", "deny", "missing"])
@pytest.mark.parametrize("destination", ["lookup_person", "update_person"])
@pytest.mark.parametrize("position", ["key", "value"])
def test_later_conflicts_preserve_canonical_and_uncertain_tokens_under_release_policy(
    decision, destination, position, caplog, capsys
):
    names = ("Joanna Taylor", "Jo Taylor", "Joseph Taylor", "Joanne Taylor")
    with _session(names, decision=decision) as session:
        canonical = session.sanitize(names[0])
        assert session.sanitize(names[1]) == canonical
        confirmed = session._entity_resolver._mention_states[-1]
        prior_audit = session._audit_sink.events[-1].model_dump_json()
        competing = session.sanitize_tool_result(
            {"people": [names[2], names[1], names[3], names[1]]}
        )
        ambiguous = competing["people"][1]
        assert competing["people"][3] == ambiguous
        assert ambiguous not in (canonical, competing["people"][0], competing["people"][2])
        assert confirmed.state is State.UNIQUE_ALIAS
        assert session._entity_resolver._mention_states[1] is confirmed
        assert session._audit_sink.events[2].model_dump_json() == prior_audit
        assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS
        arguments: dict[str, JsonValue] = (
            {canonical: {"value": ambiguous}}
            if position == "key"
            else {"people": [canonical, ambiguous]}
        )
        before = deepcopy(arguments)
        history = session.transcript
        call = ToolCall(name=destination, arguments=arguments)
        if decision == "allow":
            expected = (
                {names[0]: {"value": names[1]}}
                if position == "key"
                else {"people": list(names[:2])}
            )
            assert session.rehydrate_for_tool(call) == expected
        else:
            with pytest.raises(DataReleaseDenied) as error:
                session.rehydrate_for_tool(call)
            assert error.value.__cause__ is error.value.__context__ is None
            _assert_safe(session, names, caplog, capsys, error.value)
        assert call.arguments == before
        assert session.transcript == history
        _assert_safe(session, names, caplog, capsys, competing)


@pytest.mark.parametrize("order", list(permutations(range(3))))
@pytest.mark.parametrize("mention", ["Joanna", "Joanna Taylor"])
def test_self_alias_duplicate_evidence_cannot_hide_a_second_identity(
    order, mention, caplog, capsys
):
    names = ("Joanna Taylor", "Joseph Taylor", "Joanna", "Joseph")
    with _session(names, aliases={"Joanna": ["Joanna", "Joseph", "JOSEPH"]}) as session:
        first = session.sanitize(names[0])
        assert session.sanitize(mention) == first
        original = session._entity_resolver._mention_states[-1]
        second = session.sanitize(names[1])
        resolver = session._entity_resolver
        producers = resolver._candidate_producers
        resolver._candidate_producers = tuple(producers[index] for index in order)
        ambiguous = session.sanitize(mention)
        assert ambiguous not in (first, second)
        assert resolver._mention_states[-1].state is State.AMBIGUOUS
        assert resolver._mention_states[1] is original
        assert len(resolver._identities_by_id) == 2
        assert _release(session, first) == names[0]
        assert _release(session, second) == names[1]
        assert _release(session, ambiguous) == mention
        _assert_safe(session, names, caplog, capsys, first, second, ambiguous)


@pytest.mark.parametrize(
    ("canonical", "unrelated", "mention"),
    [
        ("Joanna Anne Taylor", "Joseph Ann Taylor", "Jo Anne Taylor"),
        ("Joanna Taylor", "Joseph Taylors", "Jo Taylor"),
        ("Joanna O'Connor", "Joseph OConnor", "Jo O'Connor"),
        ("Joanna Anne-Marie Taylor", "Joseph Anne Marie Taylor", "Jo Anne-Marie Taylor"),
        ("Joanna Taylor", "Joseph Tаylor", "Jo Taylor"),
    ],
)
@pytest.mark.parametrize("reverse", [False, True])
def test_full_remaining_components_narrow_aliases_without_fuzzy_identity_merges(
    canonical, unrelated, mention, reverse, caplog, capsys
):
    names = (canonical, unrelated, mention, "Jo")
    with _session(names) as session:
        order = (unrelated, canonical) if reverse else (canonical, unrelated)
        tokens = {name: session.sanitize(name) for name in order}
        safe = session.sanitize_tool_result({"owner": [[mention]], "bare": "Jo"})
        assert safe["owner"] == [[tokens[canonical]]]
        assert safe["bare"] not in tokens.values()
        assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS
        assert _release(session, safe["owner"][0][0]) == canonical
        assert _release(session, safe["bare"]) == "Jo"
        _assert_safe(session, names, caplog, capsys, safe)


@pytest.mark.parametrize("transcript", [False, True])
def test_alias_snapshot_mutation_close_and_fresh_session_cannot_rebind_identity(
    transcript, caplog, capsys
):
    names = (
        "Elizabeth Vale",
        "Eliza Vale",
        "Beth Vale",
        "Beth",
        "Bess Vale",
        "Bess",
        "Elizabeth",
        "Eliza",
    )
    targets = ["Elizabeth"]
    aliases = {"Beth": targets}
    sink = InMemoryAuditSink()
    gate = TrustGate(policy=_policy(), audit_sink=sink)
    with gate.session(aliases=aliases, transcript=transcript) as first:
        first._detector = NameDetector(frozenset(names))
        early = first.sanitize("Bess")
        original = first.sanitize(names[0])
        assert first.sanitize("Beth Vale") == original
        producer = first._entity_resolver._alias_resolver
        targets[:] = ["Eliza"]
        aliases["Bess"] = ["Eliza"]
        first.sanitize("Eliza Vale")
        assert first.sanitize("Beth Vale") == original
        assert first.sanitize("Bess") == early
        assert _release(first, original) == names[0]
        history = first.transcript
        with gate.session(aliases=aliases, transcript=transcript) as second:
            second._detector = NameDetector(frozenset(names))
            later = second.sanitize("Eliza Vale")
            assert second.sanitize("Beth Vale") == later
            assert second.sanitize("Bess Vale") == later
            assert second.sanitize("Bess") == later != early
            with pytest.raises(CrossSessionTokenError) as error:
                _release(second, original)
            assert_no_raw_sensitive_values(error.value, *names)
            first.close()
            assert first.transcript == history
            assert producer._aliases == frozenset()
            assert first._entity_resolver._entities_by_id == {}
            assert first._entity_resolver._unconfirmed_by_surface_form == {}
            assert first._vault._entries_by_token == {}
            assert _release(second, later, "update_person") == "Eliza Vale"
            with pytest.raises(UnknownTokenError) as error:
                _release(second, original)
            assert_no_raw_sensitive_values(error.value, *names)
            _assert_safe(second, names, caplog, capsys, early, original, later)
        with gate.session(transcript=transcript) as fresh:
            fresh._detector = NameDetector(frozenset(names))
            fresh_full = fresh.sanitize("Elizabeth Vale")
            fresh_alias = fresh.sanitize("Beth Vale")
            assert fresh_alias != fresh_full
            assert _release(fresh, fresh_alias) == "Beth Vale"
            assert fresh.sanitize("Bess") != early
            with pytest.raises(SessionClosedError) as error:
                _release(first, original)
            assert_no_raw_sensitive_values(error.value, *names)
            _assert_safe(fresh, names, caplog, capsys, fresh_alias)


@pytest.mark.parametrize(
    ("canonical", "equivalent", "partial"),
    [
        ("Dr. Ｊｏａｎｎａ　Ｔａｙｌｏｒ", "JOANNA TAYLOR", "Ｍｒ．　Ｔａｙｌｏｒ"),
        ("José Taylor", "Jose\u0301 Taylor", "Jose\u0301"),
    ],
)
def test_normalized_mentions_never_replace_the_first_canonical_tool_value(
    canonical, equivalent, partial, caplog, capsys
):
    names = (canonical, equivalent, partial)
    with _session(names) as session:
        token = session.sanitize(canonical)
        raw = {"people": [equivalent, {"followup": partial}, canonical]}
        before = deepcopy(raw)
        safe = session.sanitize_tool_result(raw)
        assert safe == {"people": [token, {"followup": token}, token]}
        assert raw == before
        for destination in ("lookup_person", "update_person"):
            assert _release(session, token, destination) == canonical
        _assert_safe(session, names, caplog, capsys, safe)


@pytest.mark.parametrize("cycle", [False, True])
@pytest.mark.parametrize("transcript", [False, True])
def test_alias_chains_and_cycles_do_not_turn_confirmed_mentions_into_new_alias_sources(
    cycle, transcript, caplog, capsys
):
    names = ("Elizabeth Vale", "Bess Vale", "Beth Vale", "Bess", "Beth", "Elizabeth")
    aliases = {"Beth": ["Bess"], "Bess": ["Elizabeth"]}
    if cycle:
        aliases["Elizabeth"] = ["Beth"]
    with _session(names, aliases=aliases, transcript=transcript) as session:
        canonical = session.sanitize(names[0])
        assert session.sanitize("Bess Vale") == canonical
        earlier = session._entity_resolver._mention_states[-1]
        # Bess resolving to Elizabeth must not create Beth -> Elizabeth transitively.
        safe = session.sanitize_tool_result({"owner": ["Beth Vale", "Bess Vale"]})
        separate = safe["owner"][0]
        assert separate != canonical
        assert safe["owner"][1] == canonical
        assert len(session._entity_resolver._identities_by_id) == 2
        assert _release(session, separate) == "Beth Vale"
        assert _release(session, canonical) == "Elizabeth Vale"
        assert earlier.state is State.UNIQUE_ALIAS
        repeated_full = session.sanitize("Elizabeth Vale")
        if cycle:
            assert repeated_full not in (canonical, separate)
            assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS
            assert session.sanitize("Elizabeth Vale") == repeated_full
            # Even though strings happen to agree, the uncertain token is a
            # distinct identity and never replaces the original canonical token.
            assert _release(session, repeated_full) == "Elizabeth Vale"
        else:
            assert repeated_full == canonical
        assert _release(session, canonical, "update_person") == "Elizabeth Vale"
        assert session.sanitize("Bess") == canonical
        _assert_safe(session, names, caplog, capsys, safe, repeated_full)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("transcript", [False, True])
def test_normalized_custom_alias_union_keeps_builtin_competitors_and_narrow_aliases(
    reverse, transcript, caplog, capsys
):
    known = ("Joanna Taylor", "Joseph Taylor", "Jocelyn Taylor", "Josette Taylor")
    mentions = ("Jo Taylor", "Jo", "Joe Taylor", "Mr Jo")
    aliases = {"Jo": ["Jocelyn"], "ＪＯ": ["JOСELYN", "Jocelyn", "Josette"]}
    # The Cyrillic C in the extra target is deliberately not fuzzy-normalized.
    with _session(known + mentions, aliases=aliases, transcript=transcript) as session:
        order = tuple(reversed(known)) if reverse else known
        tokens = {name: session.sanitize(name) for name in order}
        safe = session.sanitize_tool_result({"people": [[mention] for mention in mentions]})
        observed = [item[0] for item in safe["people"]]
        assert observed[0] not in tokens.values()
        assert observed[1] not in tokens.values()
        assert observed[0] != observed[1]
        assert observed[2] == tokens["Joseph Taylor"]
        assert observed[3] not in (*tokens.values(), *observed[:3])
        assert [item.state for item in session._entity_resolver._mention_states[-4:]] == [
            State.AMBIGUOUS,
            State.AMBIGUOUS,
            State.UNIQUE_ALIAS,
            State.UNRESOLVED,
        ]
        assert len(session._entity_resolver._identities_by_id) == 4
        assert _release(session, observed[2]) == "Joseph Taylor"
        for index in (0, 1, 3):
            assert _release(session, observed[index]) == mentions[index]
        _assert_safe(
            session, known + mentions + ("Jocelyn", "Josette", "JOСELYN"), caplog, capsys, safe
        )


@pytest.mark.parametrize("channel", ["input", "tool_result"])
@pytest.mark.parametrize("transcript", [False, True])
def test_ambiguous_full_alias_never_becomes_a_candidate_for_later_mentions(
    channel, transcript, caplog, capsys
):
    names = ("Joanna Taylor", "Joseph Taylor", "Jo Taylor", "Joe Taylor", "Mr Jo")
    with _session(names, transcript=transcript) as session:
        first = session.sanitize(names[0])
        second = session.sanitize(names[1])
        ambiguous = (
            session.sanitize("Jo Taylor")
            if channel == "input"
            else session.sanitize_tool_result({"person": ["Jo Taylor"]})["person"][0]
        )
        assert ambiguous not in (first, second)
        snapshot = tuple(session._entity_resolver._mention_states)
        safe = session.sanitize_tool_result({"people": ["Joe Taylor", "Mr Jo", "Jo Taylor"]})
        assert safe["people"][0] == second
        assert safe["people"][1] not in (first, second, ambiguous)
        assert safe["people"][2] == ambiguous
        assert tuple(session._entity_resolver._mention_states[:3]) == snapshot
        assert len(session._entity_resolver._identities_by_id) == 2
        assert _release(session, ambiguous) == "Jo Taylor"
        assert _release(session, safe["people"][0]) == "Joseph Taylor"
        _assert_safe(session, names, caplog, capsys, safe)
