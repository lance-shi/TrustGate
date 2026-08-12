"""Tests for text sanitization at the LLM boundary."""

from dataclasses import dataclass
from re import fullmatch

import pytest

from trustgate import DetectionUnavailableError, SensitiveEntity, TrustGate, TrustSession

RAW_SENTINEL = "RAW_SECRET_DO_NOT_LEAK_12345678"


@dataclass(frozen=True)
class StaticDetector:
    entities: tuple[SensitiveEntity, ...]

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        return self.entities


class FailingDetector:
    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        raise RuntimeError(f"Detection failed for {text}")


def entity(entity_type: str, start: int, end: int, score: float = 0.9) -> SensitiveEntity:
    return SensitiveEntity(entity_type=entity_type, start=start, end=end, score=score)


def test_sanitize_uses_the_local_detector_and_never_returns_detected_raw_text() -> None:
    text = "Ada Lovelace has account 12345678."

    with TrustGate().session() as session:
        sanitized = session.sanitize(text)

    assert fullmatch(
        r"\[PERSON_[1-9][0-9]*\] has account \[ACCOUNT_NUMBER_[1-9][0-9]*\]\.",
        sanitized,
    )
    assert "Ada Lovelace" not in sanitized
    assert "12345678" not in sanitized


def test_sanitize_reuses_tokens_for_repeated_sensitive_values() -> None:
    text = "Ada Lovelace met Ada Lovelace."
    session = TrustSession(
        detector=StaticDetector((entity("PERSON", 0, 12), entity("PERSON", 17, 29)))
    )

    sanitized = session.sanitize(text)

    assert fullmatch(r"\[PERSON_([1-9][0-9]*)\] met \[PERSON_\1\]\.", sanitized)
    assert "Ada Lovelace" not in sanitized


def test_sanitize_keeps_adjacent_sensitive_spans_separate() -> None:
    text = "12345678Ada Lovelace"
    session = TrustSession(
        detector=StaticDetector((entity("ACCOUNT_NUMBER", 0, 8), entity("PERSON", 8, 20)))
    )

    assert fullmatch(
        r"\[ACCOUNT_NUMBER_[1-9][0-9]*\]\[PERSON_[1-9][0-9]*\]",
        session.sanitize(text),
    )


def test_sanitize_replaces_different_length_sensitive_values() -> None:
    text = "Account 12345678 belongs to Ada Lovelace."
    session = TrustSession(
        detector=StaticDetector((entity("ACCOUNT_NUMBER", 8, 16), entity("PERSON", 28, 40)))
    )

    sanitized = session.sanitize(text)

    assert fullmatch(
        r"Account \[ACCOUNT_NUMBER_[1-9][0-9]*\] belongs to \[PERSON_[1-9][0-9]*\]\.",
        sanitized,
    )
    assert "12345678" not in sanitized
    assert "Ada Lovelace" not in sanitized


def test_sanitize_merges_overlapping_spans_so_no_detected_text_leaks() -> None:
    session = TrustSession(
        detector=StaticDetector(
            (
                entity("PERSON", 0, 20, score=0.8),
                entity("ACCOUNT_NUMBER", 10, len(RAW_SENTINEL), score=0.95),
            )
        )
    )

    sanitized = session.sanitize(RAW_SENTINEL)

    assert fullmatch(r"\[ACCOUNT_NUMBER_[1-9][0-9]*\]", sanitized)
    assert RAW_SENTINEL not in sanitized


def test_sanitize_hides_sensitive_input_when_detection_fails() -> None:
    session = TrustSession(detector=FailingDetector())

    with pytest.raises(DetectionUnavailableError) as error:
        session.sanitize(RAW_SENTINEL)

    assert RAW_SENTINEL not in str(error.value)
    assert RAW_SENTINEL not in repr(error.value)
