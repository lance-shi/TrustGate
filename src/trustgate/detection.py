"""Local, explicit Presidio detection for TrustGate's English text boundary."""

from __future__ import annotations

from pathlib import Path
from re import compile
from unicodedata import normalize

import spacy
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .entity import _is_supported_person_title
from .exceptions import DetectionUnavailableError
from .models import SensitiveEntity

DEFAULT_SPACY_MODEL = "en_core_web_sm"
SUPPORTED_ENTITIES = ("PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "ACCOUNT_NUMBER")
_LEADING_TITLE = compile(r"(?<!\w)([^\W\d_]+[.．]?)\s+$")


class PresidioDetector:
    """Detect supported sensitive entities using an already-installed local spaCy model."""

    def __init__(self, *, model_name: str = DEFAULT_SPACY_MODEL) -> None:
        try:
            # Presidio otherwise attempts to download a missing model. Refuse
            # before calling it, without logging the supplied name or path.
            if not (spacy.util.is_package(model_name) or Path(model_name).exists()):
                raise DetectionUnavailableError
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
            failed = True
        else:
            failed = False
        if failed:
            raise DetectionUnavailableError

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        """Return detected entity metadata without retaining or returning raw text."""
        try:
            results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=list(SUPPORTED_ENTITIES),
            )
        except Exception:
            results = None
        if results is None:
            raise DetectionUnavailableError

        return tuple(
            SensitiveEntity(
                entity_type=result.entity_type,
                start=(
                    _person_start_with_title(text, result.start)
                    if result.entity_type == "PERSON"
                    else result.start
                ),
                end=result.end,
                score=result.score,
            )
            for result in sorted(
                results,
                key=lambda result: (result.start, result.end, result.entity_type),
            )
        )


def _person_start_with_title(text: str, start: int) -> int:
    """Include an immediately preceding supported title in a PERSON span.

    Presidio often detects only the surname in 'Mr Smith'. Preserve that
    context for surname resolution, using original offsets after Unicode
    normalization of just the title. Never search for undetected names.
    """
    match = _LEADING_TITLE.search(text[:start])
    if match and _is_supported_person_title(normalize("NFKC", match.group(1)).casefold()):
        return match.start(1)
    return start
