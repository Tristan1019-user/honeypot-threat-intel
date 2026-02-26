"""
Unit tests for previously uncovered internals:
  1. is_malware_vt_enriched() — correct semantics for three states
  2. Keyset cursor encode/decode — roundtrip, bad input, padding edge cases
  3. _PIPELINE_LOCK — concurrent calls queue, not interleave
  4. _indicator_id() — stable, collision-free, no truncation
"""
import asyncio
import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.database import (
    _decode_pg_cursor,
    _encode_pg_cursor,
    _sanitize_params,
    insert_malware,
    is_malware_vt_enriched,
    update_malware_vt,
)
from app.pipeline import _indicator_id, _PIPELINE_LOCK


# ── 1. is_malware_vt_enriched ─────────────────────────────────────────────────

def test_is_malware_vt_enriched_returns_false_when_sample_missing(db_path):
    result = asyncio.run(is_malware_vt_enriched("a" * 64))
    assert result is False


def test_is_malware_vt_enriched_returns_false_when_vt_enriched_at_is_null(db_path):
    """Sample exists in DB but VT enrichment has NOT been done yet."""
    sha = "b" * 64
    asyncio.run(insert_malware({
        "sha256": sha,
        "session_id": "sess-001",
        "url": "http://evil.example/payload",
        "first_seen": "2026-01-01T00:00:00Z",
    }))
    # No update_malware_vt call — vt_enriched_at is NULL
    result = asyncio.run(is_malware_vt_enriched(sha))
    assert result is False


def test_is_malware_vt_enriched_returns_true_after_enrichment(db_path):
    """Sample exists AND vt_enriched_at is set → already enriched, skip VT."""
    sha = "c" * 64
    asyncio.run(insert_malware({
        "sha256": sha,
        "session_id": "sess-002",
        "url": "http://evil.example/bot",
        "first_seen": "2026-01-01T00:00:00Z",
    }))
    asyncio.run(update_malware_vt(sha, {
        "vt_known": True,
        "vt_detection_ratio": "30/72",
        "vt_malware_families": ["Mirai"],
        "vt_first_submission": 1700000000,
    }))
    result = asyncio.run(is_malware_vt_enriched(sha))
    assert result is True


# ── 2. Keyset cursor encode/decode ─────────────────────────────────────────────

def test_encode_decode_cursor_roundtrip():
    last_seen = "2026-01-15T03:22:10Z"
    last_id = "indicator-ipv4-addr-abc123def456"
    cursor = _encode_pg_cursor(last_seen, last_id)
    assert cursor  # non-empty string
    decoded = _decode_pg_cursor(cursor)
    assert decoded is not None
    ts, id_ = decoded
    assert ts == last_seen
    assert id_ == last_id


def test_encode_decode_cursor_with_none_last_seen():
    """NULL last_seen (empty string in encoding) round-trips correctly."""
    cursor = _encode_pg_cursor(None, "some-id")
    decoded = _decode_pg_cursor(cursor)
    assert decoded is not None
    ts, id_ = decoded
    assert ts is None  # empty string → None
    assert id_ == "some-id"


def test_decode_cursor_returns_none_on_garbage():
    assert _decode_pg_cursor("not-valid-base64!!!") is None
    assert _decode_pg_cursor("") is None
    assert _decode_pg_cursor("aGVsbG8=") is None  # valid b64, no "|" separator


def test_decode_cursor_returns_none_on_integer_offset_cursor():
    """Old-style OFFSET cursors (plain integers) must not silently parse as keyset."""
    result = _decode_pg_cursor("100")   # "100" decoded from base64 is garbage
    assert result is None


def test_cursor_padding_edge_cases():
    """Base64 requires padding; test strings that produce 0, 1, 2 padding chars."""
    for suffix_len in range(1, 20):
        id_ = "x" * suffix_len
        cursor = _encode_pg_cursor("2026-01-01T00:00:00Z", id_)
        decoded = _decode_pg_cursor(cursor)
        assert decoded is not None, f"Failed for id length {suffix_len}"
        ts, decoded_id = decoded
        assert decoded_id == id_, f"ID mismatch for length {suffix_len}"


def test_sanitize_params_strips_nul_recursively():
    params = (
        "abc\x00def",
        ["x\x00y", {"k": "v\x00"}],
        {"nested": ("1\x002",)},
    )
    sanitized = _sanitize_params(params)
    assert sanitized[0] == "abcdef"
    assert sanitized[1][0] == "xy"
    assert sanitized[1][1]["k"] == "v"
    assert sanitized[2]["nested"][0] == "12"


# ── 3. _PIPELINE_LOCK — concurrent calls queue ───────────────────────────────

def test_pipeline_lock_prevents_concurrent_runs():
    """Two concurrent process_cowrie_log calls must not interleave.

    We patch _run_pipeline to record execution order and verify the second
    call starts only after the first completes (not interleaved).
    """
    execution_log: list[str] = []

    async def fake_run_pipeline(*args, **kwargs):
        execution_log.append("start")
        await asyncio.sleep(0.05)  # simulate async work
        execution_log.append("end")
        return {}

    async def run_concurrent():
        from app.pipeline import process_cowrie_log
        with patch("app.pipeline._run_pipeline", side_effect=fake_run_pipeline):
            await asyncio.gather(
                process_cowrie_log("/fake/log"),
                process_cowrie_log("/fake/log"),
            )

    asyncio.run(run_concurrent())
    # Correct: start, end, start, end (sequential)
    # Wrong:   start, start, end, end (interleaved)
    assert execution_log == ["start", "end", "start", "end"], (
        f"Pipeline calls interleaved: {execution_log}"
    )


# ── 4. _indicator_id() ────────────────────────────────────────────────────────

def test_indicator_id_is_stable():
    """Same inputs always produce the same id."""
    assert _indicator_id("ipv4-addr", "1.2.3.4") == _indicator_id("ipv4-addr", "1.2.3.4")


def test_indicator_id_differs_across_types():
    """Same value with different types must produce different ids."""
    a = _indicator_id("url", "1.2.3.4")
    b = _indicator_id("ipv4-addr", "1.2.3.4")
    assert a != b


def test_indicator_id_no_collision_for_long_urls():
    """URLs sharing a long common prefix must produce different ids."""
    base = "http://malware.example.com/download/payloads/arm/mips/bot-"
    id1 = _indicator_id("url", base + "v1")
    id2 = _indicator_id("url", base + "v2")
    assert id1 != id2


def test_indicator_id_no_collision_for_hash_prefix():
    """SHA-256s sharing a common prefix must produce different ids."""
    sha_a = "a" * 63 + "0"
    sha_b = "a" * 63 + "1"
    id1 = _indicator_id("file-hash", sha_a)
    id2 = _indicator_id("file-hash", sha_b)
    assert id1 != id2


def test_indicator_id_format():
    """Id has the expected structure: indicator-{type}-{32 hex chars}."""
    import re
    id_ = _indicator_id("ipv4-addr", "192.0.2.1")
    assert re.fullmatch(r"indicator-ipv4-addr-[0-9a-f]{32}", id_), id_
