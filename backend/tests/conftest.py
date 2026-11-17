import os
import tempfile
from pathlib import Path

import pytest

_DB_DIR = tempfile.mkdtemp(prefix="vigil-test-")
os.environ["VIGIL_DATABASE_URL"] = f"sqlite:///{Path(_DB_DIR) / 'test.db'}"
os.environ["VIGIL_JWT_SECRET"] = "test-secret-" + "x" * 40
os.environ["VIGIL_INGEST_TOKEN"] = "test-ingest-token"


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_headers(client):
    r = client.post("/api/auth/register", json={"username": "admin", "password": "correct-horse"})
    assert r.status_code == 201, r.text
    assert r.json()["user"]["role"] == "admin"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
