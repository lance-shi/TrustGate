"""Session ownership and cleanup tests for the internal token vault."""

import pytest

from trustgate import CrossSessionTokenError, MalformedTokenError, TrustGate, UnknownTokenError


def test_each_session_owns_a_distinct_private_vault() -> None:
    gate = TrustGate()
    first = gate.session()
    second = gate.session()

    assert first._vault is not second._vault


def test_close_clears_issued_token_mappings_and_is_idempotent() -> None:
    session = TrustGate().session()
    token = session._vault.store(
        value="RAW_SECRET_DO_NOT_LEAK_12345678", entity_type="ACCOUNT_NUMBER"
    )

    session.close()
    session.close()

    assert session.is_closed
    with pytest.raises(UnknownTokenError):
        session._vault.resolve(token.value)


def test_active_session_rejects_a_valid_token_issued_by_another_session() -> None:
    gate = TrustGate()
    first = gate.session()
    second = gate.session()
    foreign_token = second._vault.store(
        value="RAW_SECRET_DO_NOT_LEAK_12345678", entity_type="ACCOUNT_NUMBER"
    )

    with pytest.raises(CrossSessionTokenError) as error:
        first._vault.resolve(foreign_token.value)

    assert foreign_token.value not in str(error.value)
    assert foreign_token.value not in repr(error.value)
    assert "RAW_SECRET_DO_NOT_LEAK_12345678" not in str(error.value)
    assert "RAW_SECRET_DO_NOT_LEAK_12345678" not in repr(error.value)


@pytest.mark.parametrize("malformed_token", ["ACCOUNT_NUMBER_1", "[account_number_1]", "[]"])
def test_malformed_token_fails_without_disclosing_its_input(malformed_token: str) -> None:
    session = TrustGate().session()

    with pytest.raises(MalformedTokenError) as error:
        session._vault.resolve(malformed_token)

    assert malformed_token not in str(error.value)
    assert malformed_token not in repr(error.value)
