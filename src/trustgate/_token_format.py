"""Shared syntax for opaque, session-namespaced tokens."""

from re import compile

TOKEN_EXPRESSION = r"^\[[A-Z][A-Z0-9_]*_[0-9a-f]{32}_[1-9][0-9]*\]$"
TOKEN_PATTERN = compile(TOKEN_EXPRESSION)
