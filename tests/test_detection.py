"""Tests for local Presidio and spaCy sensitive-entity detection."""

import pytest

from trustgate import DetectionUnavailableError
from trustgate.detection import PresidioDetector


def test_detector_returns_project_entities_with_correct_text_ranges() -> None:
    text = "Ada Lovelace has account 12345678."

    entities = PresidioDetector().detect(text)

    assert [(entity.entity_type, entity.start, entity.end) for entity in entities] == [
        ("PERSON", 0, 12),
        ("ACCOUNT_NUMBER", 25, 33),
    ]
    assert [text[entity.start : entity.end] for entity in entities] == ["Ada Lovelace", "12345678"]


def test_unavailable_local_model_fails_without_disclosing_sensitive_text() -> None:
    raw_text = "RAW_SECRET_DO_NOT_LEAK_12345678"

    with pytest.raises(DetectionUnavailableError) as error:
        PresidioDetector(model_name="trustgate_missing_spacy_model")

    assert raw_text not in str(error.value)
    assert raw_text not in repr(error.value)
