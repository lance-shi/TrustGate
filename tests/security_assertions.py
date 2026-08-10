"""Reusable assertions for TrustGate's no-raw-value security invariant."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel


def assert_no_raw_sensitive_values(value: object, *raw_values: str) -> None:
    """Fail without echoing sensitive input if any raw value is reachable.

    This intentionally inspects exception arguments and chaining metadata as
    well as ordinary nested values. It should be used for every LLM-visible
    value, audit event, exception, and future log record in the test suite.
    """
    rendered = "\n".join(_render_views(value, seen=set()))
    for raw_value in raw_values:
        if raw_value and raw_value in rendered:
            raise AssertionError("A raw sensitive test value was disclosed.")


def _render_views(value: object, *, seen: set[int]) -> list[str]:
    object_id = id(value)
    if object_id in seen:
        return []
    seen.add(object_id)

    if isinstance(value, BaseException):
        views = [str(value), repr(value)]
        for item in value.args:
            views.extend(_render_views(item, seen=seen))
        if value.__cause__ is not None:
            views.extend(_render_views(value.__cause__, seen=seen))
        if value.__context__ is not None:
            views.extend(_render_views(value.__context__, seen=seen))
        return views

    if isinstance(value, BaseModel):
        return [value.model_dump_json()]

    if isinstance(value, str):
        return [value]

    if isinstance(value, Mapping):
        views: list[str] = []
        for key, item in value.items():
            views.extend(_render_views(key, seen=seen))
            views.extend(_render_views(item, seen=seen))
        return views

    if isinstance(value, Sequence):
        views = []
        for item in value:
            views.extend(_render_views(item, seen=seen))
        return views

    try:
        return [json.dumps(value, default=_json_default, sort_keys=True)]
    except (TypeError, ValueError):
        return [repr(value)]


def _json_default(value: Any) -> str:
    return repr(value)
