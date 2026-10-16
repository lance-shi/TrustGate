"""Tests for local Presidio and spaCy sensitive-entity detection."""

from types import SimpleNamespace

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import DetectionUnavailableError
from trustgate.detection import PresidioDetector, _person_start_with_title


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


@pytest.mark.parametrize("title", ["Mr", "MR.", "Mrs.", "Ms", "Dr.", "Ｍｒ．"])
def test_detected_surname_retains_an_adjacent_supported_title(title: str) -> None:
    text = f"Ask ({title} Smith)."
    start = text.index("Smith")
    assert _person_start_with_title(text, start) == text.index(title)


@pytest.mark.parametrize("prefix", ["Customer ", "Prof. ", "customerMr ", "Mr, ", "Mr said "])
def test_title_extension_does_not_consume_unrelated_context(prefix: str) -> None:
    text = f"{prefix}Smith"
    start = text.index("Smith")
    assert _person_start_with_title(text, start) == start


def test_missing_model_never_reaches_presidio_download_path(monkeypatch, caplog) -> None:
    def unexpected_provider(*args, **kwargs):
        pytest.fail("Missing local model reached the Presidio provider.")

    monkeypatch.setattr("trustgate.detection.NlpEngineProvider", unexpected_provider)
    with pytest.raises(DetectionUnavailableError) as error:
        PresidioDetector(model_name="RAW_MODEL_PATH_DO_NOT_LEAK_missing")
    assert error.value.__context__ is error.value.__cause__ is None
    assert_no_raw_sensitive_values((error.value, caplog.text), "RAW_MODEL_PATH_DO_NOT_LEAK_missing")


def test_detector_analyzer_failure_drops_sensitive_exception_context() -> None:
    class FailingAnalyzer:
        def analyze(self, **kwargs):
            raise RuntimeError(kwargs["text"])

    detector = object.__new__(PresidioDetector)
    detector._analyzer = FailingAnalyzer()
    with pytest.raises(DetectionUnavailableError) as error:
        detector.detect("RAW_PERSON_DO_NOT_LEAK")
    assert error.value.__context__ is error.value.__cause__ is None
    assert_no_raw_sensitive_values(error.value, "RAW_PERSON_DO_NOT_LEAK")


def test_title_context_changes_only_person_detection_spans() -> None:
    class Analyzer:
        def analyze(self, **kwargs):
            return [
                SimpleNamespace(entity_type="PERSON", start=3, end=8, score=0.9),
                SimpleNamespace(entity_type="ACCOUNT_NUMBER", start=12, end=20, score=0.9),
            ]

    detector = object.__new__(PresidioDetector)
    detector._analyzer = Analyzer()
    text = "Mr Smith Mr 12345678"
    entities = detector.detect(text)
    assert [(entity.start, entity.end) for entity in entities] == [(0, 8), (12, 20)]


def test_provider_initialization_failure_cannot_retain_sensitive_exception_context(
    monkeypatch,
) -> None:
    def failing_provider(**kwargs):
        raise RuntimeError("RAW_DETECTOR_CONFIGURATION_DO_NOT_LEAK")

    monkeypatch.setattr("trustgate.detection.NlpEngineProvider", failing_provider)
    with pytest.raises(DetectionUnavailableError) as error:
        PresidioDetector()
    assert error.value.__context__ is error.value.__cause__ is None
    assert_no_raw_sensitive_values(error.value, "RAW_DETECTOR_CONFIGURATION_DO_NOT_LEAK")
