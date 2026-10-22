"""Tests for the process-local, in-memory token vault."""

import re

import pytest

from trustgate import UnknownTokenError
from trustgate.vault import TokenVault

RAW_ACCOUNT = "RAW_ACCOUNT_DO_NOT_LEAK_12345678"


def test_store_creates_a_token_and_resolve_returns_its_internal_mapping() -> None:
    vault = TokenVault()

    token = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    entry = vault.resolve(token.value)

    assert re.fullmatch(r"\[ACCOUNT_NUMBER_[0-9a-f]{32}_1\]", token.value)
    assert token.entity_type == "ACCOUNT_NUMBER"
    assert entry.value == RAW_ACCOUNT
    assert entry.entity_type == "ACCOUNT_NUMBER"


def test_store_reuses_a_token_for_the_same_value_and_entity_type() -> None:
    vault = TokenVault()

    first = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    second = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    assert second == first


def test_store_uses_a_new_token_for_a_different_value_of_the_same_type() -> None:
    vault = TokenVault()

    first = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    second = vault.store(value="RAW_ACCOUNT_DO_NOT_LEAK_87654321", entity_type="ACCOUNT_NUMBER")

    assert re.fullmatch(r"\[ACCOUNT_NUMBER_[0-9a-f]{32}_1\]", first.value)
    assert re.fullmatch(r"\[ACCOUNT_NUMBER_[0-9a-f]{32}_2\]", second.value)
    assert first != second


def test_store_uses_independent_sequences_for_entity_types() -> None:
    vault = TokenVault()

    account = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    person = vault.store(value="Ada Lovelace", entity_type="PERSON")

    assert re.fullmatch(r"\[ACCOUNT_NUMBER_[0-9a-f]{32}_1\]", account.value)
    assert re.fullmatch(r"\[PERSON_[0-9a-f]{32}_1\]", person.value)


def test_unknown_token_fails_without_disclosing_the_requested_value() -> None:
    vault = TokenVault()
    unknown_token = "[ACCOUNT_NUMBER_00000000000000000000000000000000_99]"

    with pytest.raises(UnknownTokenError) as error:
        vault.resolve(unknown_token)

    assert unknown_token not in str(error.value)
    assert unknown_token not in repr(error.value)


def test_clear_removes_all_raw_mappings() -> None:
    vault = TokenVault()
    token = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    vault.clear()

    with pytest.raises(UnknownTokenError):
        vault.resolve(token.value)


def test_identity_tokens_do_not_merge_just_because_raw_values_are_equal() -> None:
    vault = TokenVault()
    first = vault.store(value="John", entity_type="PERSON", identity_id="first")
    second = vault.store(value="John", entity_type="PERSON", identity_id="second")
    by_value = vault.store(value="John", entity_type="PERSON")
    assert len({first.value, second.value, by_value.value}) == 3
    assert vault.store(value="John", entity_type="PERSON", identity_id="first") == first
    vault.clear()
    for token in (first, second, by_value):
        with pytest.raises(UnknownTokenError):
            vault.resolve(token.value)


def test_identity_token_canonical_value_cannot_be_overwritten() -> None:
    vault = TokenVault()
    token = vault.store(value="John Smith", entity_type="PERSON", identity_id="first")
    with pytest.raises(ValueError) as error:
        vault.store(value="Larry Smith", entity_type="PERSON", identity_id="first")
    assert vault.resolve(token.value).value == "John Smith"
    for raw in ("John Smith", "Larry Smith"):
        assert raw not in str(error.value)
        assert raw not in repr(error.value)
