import pytest
from fastapi.testclient import TestClient

import api


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(api, "API_KEY", "")
    with TestClient(api.app) as client:
        yield client


def test_health_never_loads_the_remote_catalog(client, monkeypatch):
    async def offline():
        raise AssertionError("Liveness contacted CISA")

    monkeypatch.setattr(api, "get_kev_client", offline)
    monkeypatch.setattr(api, "_kev_client", None)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["kev_catalog_loaded"] is False


def test_api_key_protects_reports_and_keeps_liveness_public(client, monkeypatch):
    monkeypatch.setattr(api, "API_KEY", "test-key")
    assert client.get("/health").status_code == 200
    assert client.get("/report/private.json").status_code == 401
    assert client.get("/report/private.json", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/report/not-present.json", headers={"X-API-Key": "test-key"}).status_code == 404


def test_inventory_is_bounded_before_scanning(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_INVENTORY_BYTES", 16)
    response = client.post("/scan", files={"inventory": ("inventory.csv", b"x" * 17)})
    assert response.status_code == 413


def test_browser_origins_are_not_unrestricted(client):
    response = client.get("/health", headers={"Origin": "https://attacker.example"})
    assert "access-control-allow-origin" not in response.headers


def test_authenticated_browser_preflight_reaches_cors(client, monkeypatch):
    monkeypatch.setattr(api, "API_KEY", "test-key")
    response = client.options(
        "/scan",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key",
        },
    )
    # CORS rejects the unconfigured origin; authentication must not turn the
    # preflight into a 401, since browsers never send API keys on OPTIONS.
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
    assert client.options("/scan").status_code == 401
