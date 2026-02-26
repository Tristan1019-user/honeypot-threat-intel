"""Shared utility functions used across the app and routers.

Centralising parse_since() here prevents a circular import:
  routers/taxii.py → app.main → routers/taxii.py
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException


def parse_since(since: Optional[str]) -> Optional[str]:
    """Parse the 'since' / 'added_after' time filter parameter.

    Accepts:
      - ISO 8601 timestamps  (2026-02-20T00:00:00Z)
      - Relative durations   (1h, 6h, 24h, 7d, 30d, 1w)
      - Unix epoch seconds   (1708387200)

    Returns an ISO 8601 timestamp string, or None if the input is None/empty.
    Raises HTTP 400 on unrecognised format so callers get a clear error message.
    """
    if not since:
        return None

    rel_match = re.match(r'^(\d+)([hdwm])$', since.strip().lower())
    if rel_match:
        amount = int(rel_match.group(1))
        unit = rel_match.group(2)
        delta_map = {
            'h': timedelta(hours=amount),
            'd': timedelta(days=amount),
            'w': timedelta(weeks=amount),
            'm': timedelta(days=amount * 30),
        }
        dt = datetime.now(timezone.utc) - delta_map[unit]
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        epoch = float(since)
        if epoch > 0:
            return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError, OverflowError):
        pass

    try:
        dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    raise HTTPException(
        status_code=400,
        detail=(
            f"Invalid 'since' / 'added_after' format: '{since}'. "
            "Accepted: ISO 8601 (2026-02-20T00:00:00Z), "
            "relative (1h, 6h, 24h, 7d, 30d, 1w), or Unix epoch seconds."
        ),
    )
