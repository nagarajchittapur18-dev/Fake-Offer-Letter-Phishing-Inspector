"""
pytest conftest — initialize the test database before API tests run.
Uses a temporary file database so connections share state within the session.
"""
import asyncio
import os
import sys
import tempfile

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Point DB at a temp file that persists for the whole session
_tmp_db = tempfile.mktemp(suffix=".db")
os.environ["DB_PATH"] = _tmp_db

import pytest


@pytest.fixture(scope="session", autouse=True)
def _init_database():
    """Run database initialisation before the test session starts."""
    from services.history.database import init_db
    asyncio.get_event_loop().run_until_complete(init_db())

