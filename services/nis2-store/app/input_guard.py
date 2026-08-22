"""
app/input_guard.py — Input size and content guards.

Provides helpers that replicate the *spirit* of C-level buffer-overflow
protection in a managed-runtime (Python) web context:

  Classic C overflow → write past buffer end → corrupt memory / code exec
  Python equivalent  → no memory corruption, but:
    • Huge TEXT fields  → exhaust DB/memory (heap DoS)
    • Huge form bodies  → exhaust gunicorn worker memory
    • Huge file uploads → OOM / disk exhaustion
    • Excessive JSON    → CPU exhaustion during parse

We defend at 4 layers (same principle as stack canaries + DEP + ASLR):
  1. MAX_CONTENT_LENGTH in config  → Flask rejects oversized HTTP bodies (413)
  2. trunc() helper               → truncate string fields before DB write
  3. check_file_size()            → reject oversized uploads before .read()
  4. safe_form() / safe_json()    → sanitize form/JSON dicts in one call
"""

from __future__ import annotations

import logging
from typing import Any

from flask import current_app, abort, request

logger = logging.getLogger(__name__)

# ── Default limits (overridden by app.config values) ─────────────────────────
_DEFAULT_MAX_TEXT   = 100_000  # 100 KB
_DEFAULT_MAX_STRING = 1_000    # 1 KB
_DEFAULT_MAX_FILE   = 1 * 1024 * 1024  # 1 MB


def _cfg(key: str, default: int) -> int:
    try:
        return int(current_app.config.get(key, default))
    except RuntimeError:  # no app context
        return default


# ── Public API ────────────────────────────────────────────────────────────────

def trunc(value: Any, max_len: int | None = None, *, field: str = '') -> str:
    """
    Coerce *value* to str and truncate to *max_len* characters.

    If max_len is None, uses MAX_STRING_FIELD from config (1 KB).
    Logs a warning when truncation occurs so it shows up in audit logs.

    Usage:
        risk.title = trunc(form.get('title', ''))
        risk.description = trunc(form.get('description', ''), max_len=MAX_TEXT)
    """
    if max_len is None:
        max_len = _cfg('MAX_STRING_FIELD', _DEFAULT_MAX_STRING)

    text = str(value or '').strip()
    if len(text) > max_len:
        logger.warning(
            'INPUT_GUARD: field %r truncated from %d → %d chars (possible attack)',
            field or '?', len(text), max_len,
        )
        text = text[:max_len]
    return text


def trunc_text(value: Any, *, field: str = '') -> str:
    """Truncate to MAX_TEXT_FIELD (100 KB) — for Text/Markdown columns."""
    return trunc(value, _cfg('MAX_TEXT_FIELD', _DEFAULT_MAX_TEXT), field=field)


def check_file_size(file_storage, *, abort_on_exceed: bool = True) -> bool:
    """
    Check that a FileStorage object doesn't exceed MAX_FILE_BYTES.

    Reads the file length WITHOUT loading the full content (seeks to end).
    Returns True if OK, False if too large (or aborts with 413 if abort_on_exceed).

    Usage:
        file = request.files['csv_file']
        check_file_size(file)          # raises 413 if too big
        content = file.read().decode()
    """
    max_bytes = _cfg('MAX_FILE_BYTES', _DEFAULT_MAX_FILE)

    # Seek to end to measure size without reading into memory
    file_storage.seek(0, 2)      # SEEK_END
    size = file_storage.tell()
    file_storage.seek(0)         # rewind

    if size > max_bytes:
        logger.warning(
            'INPUT_GUARD: file upload %r size %d B exceeds limit %d B',
            getattr(file_storage, 'filename', '?'), size, max_bytes,
        )
        if abort_on_exceed:
            abort(413)
        return False
    return True


def safe_form(form: dict | None = None, *,
              text_fields: tuple[str, ...] = (),
              max_len: int | None = None) -> dict[str, str]:
    """
    Return a cleaned copy of *form* (defaults to request.form) where:
      • Every value is stripped
      • String fields are truncated to MAX_STRING_FIELD
      • Fields listed in *text_fields* are truncated to MAX_TEXT_FIELD

    Usage:
        data = safe_form(text_fields=('description', 'affected_systems'))
        title = data['title']
    """
    raw = form if form is not None else request.form
    max_str  = max_len or _cfg('MAX_STRING_FIELD', _DEFAULT_MAX_STRING)
    max_text = _cfg('MAX_TEXT_FIELD', _DEFAULT_MAX_TEXT)

    result: dict[str, str] = {}
    for key, val in raw.items():
        limit = max_text if key in text_fields else max_str
        result[key] = trunc(val, limit, field=key)
    return result


def safe_json(data: dict | None = None, *,
              text_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    """
    Return a cleaned copy of *data* (defaults to request.get_json() or {}).
    String values are truncated; non-string values pass through unchanged.

    Usage:
        data = safe_json(text_fields=('content',))
        company_name = data.get('company_name', '')
    """
    raw = data if data is not None else (request.get_json(silent=True) or {})
    if not isinstance(raw, dict):
        abort(400)

    max_str  = _cfg('MAX_STRING_FIELD', _DEFAULT_MAX_STRING)
    max_text = _cfg('MAX_TEXT_FIELD', _DEFAULT_MAX_TEXT)

    result: dict[str, Any] = {}
    for key, val in raw.items():
        if isinstance(val, str):
            limit = max_text if key in text_fields else max_str
            result[key] = trunc(val, limit, field=key)
        else:
            result[key] = val
    return result
