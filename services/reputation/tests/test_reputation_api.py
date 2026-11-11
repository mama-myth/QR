import pytest
from fastapi.testclient import TestClient
from services.reputation.app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_lookup_valid_hash_token_unknown():
    # Valid 64-char hex token
    valid_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    response = client.post("/v1/reputation/lookup", json={"lookup_token": valid_token})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNKNOWN"
    assert data["token_prefix"] == valid_token[:16]

def test_lookup_valid_hash_token_malicious():
    # Token matching known malicious prefix
    malicious_token = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    response = client.post("/v1/reputation/lookup", json={"lookup_token": malicious_token})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "VERIFIED_MALICIOUS"
    assert data["reputation_score"] == 0.95

def test_rejects_raw_url_scheme():
    # Attempt to leak raw URL
    response = client.post("/v1/reputation/lookup", json={"lookup_token": "https://malicious.example.com"})
    assert response.status_code == 422

def test_rejects_url_path_and_query_characters():
    # Attempt to leak query or path tokens
    response = client.post("/v1/reputation/lookup", json={"lookup_token": "token/with/path?param=1"})
    assert response.status_code == 422

def test_rejects_pii_characters():
    # Attempt to send email / VPA / credentials
    response = client.post("/v1/reputation/lookup", json={"lookup_token": "user@okaxis"})
    assert response.status_code == 422
