"""Tests for the process-local, in-memory token vault."""

import pytest

from trustgate import UnknownTokenError
from trustgate.vault import TokenVault

RAW_ACCOUNT = "RAW_ACCOUNT_DO_NOT_LEAK_12345678"


def test_store_creates_a_token_and_resolve_returns_its_internal_mapping() -> None:
    vault = TokenVault()

    token = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    entry = vault.resolve(token.value)

    assert token.value == "[ACCOUNT_NUMBER_1]"
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

    assert first.value == "[ACCOUNT_NUMBER_1]"
    assert second.value == "[ACCOUNT_NUMBER_2]"
    assert first != second


def test_store_uses_independent_sequences_for_entity_types() -> None:
    vault = TokenVault()

    account = vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    person = vault.store(value="Ada Lovelace", entity_type="PERSON")

    assert account.value == "[ACCOUNT_NUMBER_1]"
    assert person.value == "[PERSON_1]"


def test_unknown_token_fails_without_disclosing_the_requested_value() -> None:
    vault = TokenVault()
    unknown_token = "[ACCOUNT_NUMBER_99]"

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
