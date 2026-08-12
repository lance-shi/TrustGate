"""Local, explicit Presidio detection for TrustGate's English text boundary."""

from __future__ import annotations

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .exceptions import DetectionUnavailableError
from .models import SensitiveEntity

DEFAULT_SPACY_MODEL = "en_core_web_sm"
SUPPORTED_ENTITIES = ("PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "ACCOUNT_NUMBER")


class PresidioDetector:
    """Detect supported sensitive entities using an already-installed local spaCy model."""

    def __init__(self, *, model_name: str = DEFAULT_SPACY_MODEL) -> None:
        try:
            nlp_engine = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model_name}],
                }
            ).create_engine()
            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            self._analyzer.registry.add_recognizer(
                PatternRecognizer(
                    supported_entity="ACCOUNT_NUMBER",
                    patterns=[
                        Pattern(
                            name="eight_digit_account_number",
                            regex=r"\b\d{8}\b",
                            score=0.85,
                        )
                    ],
                )
            )
        except Exception:
            raise DetectionUnavailableError from None

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        """Return detected entity metadata without retaining or returning raw text."""
        try:
            results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=list(SUPPORTED_ENTITIES),
            )
        except Exception:
            raise DetectionUnavailableError from None

        return tuple(
            SensitiveEntity(
                entity_type=result.entity_type,
                start=result.start,
                end=result.end,
                score=result.score,
            )
            for result in sorted(
                results,
                key=lambda result: (result.start, result.end, result.entity_type),
            )
        )
