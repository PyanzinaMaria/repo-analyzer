from __future__ import annotations


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert "python" in payload["enabled_languages"]
    assert "javascript" in payload["registered_languages"]
    assert "javascript" in payload["enabled_languages"]   # JS/TS handler is implemented (ESLint, Semgrep, CodeQL)
