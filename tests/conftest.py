import asyncio
import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Private-IP pattern extended to cover "testclient" — the host Starlette's
# TestClient uses. Needed for any endpoint that calls check_admin_auth().
_LAN_RE = re.compile(
    r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|testclient)"
)


@pytest.fixture
def client(tmp_path: Path):
    """Unauthenticated test client (no ADMIN_TOKEN, no LAN IP simulation)."""
    os.environ["DATABASE_PATH"] = str(tmp_path / "test.db")
    os.environ["ALLOW_SQLITE_FALLBACK"] = "true"
    os.environ.pop("DATABASE_URL", None)
    from app import database as db
    asyncio.run(db.init_db())
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture
def lan_client(tmp_path: Path):
    """Test client simulating a LAN caller with no ADMIN_TOKEN configured.

    Patches _PRIVATE_IP_RE so check_admin_auth() treats 'testclient' as
    a private IP (Layer 2 pass). Layer 3 is skipped since ADMIN_TOKEN is
    empty in the test environment.
    """
    os.environ["DATABASE_PATH"] = str(tmp_path / "test.db")
    os.environ["ALLOW_SQLITE_FALLBACK"] = "true"
    os.environ.pop("DATABASE_URL", None)
    from app import database as db
    asyncio.run(db.init_db())
    from app.main import app
    with patch("app.auth._PRIVATE_IP_RE", _LAN_RE):
        with TestClient(app) as c:
            yield c


@pytest.fixture
def db_path(tmp_path: Path):
    """Return a fresh SQLite DB path and initialise the schema."""
    path = str(tmp_path / "test.db")
    os.environ["DATABASE_PATH"] = path
    os.environ["ALLOW_SQLITE_FALLBACK"] = "true"
    os.environ.pop("DATABASE_URL", None)
    from app import database as db
    asyncio.run(db.init_db())
    return path
