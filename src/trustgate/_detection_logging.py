"""Keep dependency diagnostics out of sensitive local detection calls."""

from contextlib import contextmanager
from contextvars import ContextVar
from logging import Filter, LogRecord, getLogger
from typing import Iterator

_DETECTING: ContextVar[bool] = ContextVar("trustgate_private_detection", default=False)


class _DetectionLogFilter(Filter):
    def filter(self, record: LogRecord) -> bool:
        # Filtering on the emitting logger also covers its own handlers,
        # before records can propagate to host/root handlers.
        return not _DETECTING.get()


_FILTER = _DetectionLogFilter()


@contextmanager
def _private_detection_logs() -> Iterator[None]:
    # Presidio uses these concrete logger names (not module-name children).
    # Never change levels, handlers, or global logging.disable: other threads
    # and callers outside this context must retain their own logging behavior.
    for name in ("presidio-analyzer", "decision_process"):
        getLogger(name).addFilter(_FILTER)
    context = _DETECTING.set(True)
    try:
        yield
    finally:
        _DETECTING.reset(context)
