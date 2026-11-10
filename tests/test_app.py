"""Unit tests, including the security behaviour the app claims to have."""
from __future__ import annotations

import pytest

from app.main import MAX_TITLE, SECURITY_HEADERS, create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(database=str(tmp_path / "test.db"))
    app.config["TESTING"] = True
    return app.test_client()


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_create_list_and_fetch_note(client):
    created = client.post("/notes", json={"title": " First ", "body": "hello"})
    assert created.status_code == 201
    note_id = created.get_json()["id"]
    assert client.get("/notes").get_json() == [{"id": note_id, "title": "First"}]
    assert client.get(f"/notes/{note_id}").get_json()["body"] == "hello"


@pytest.mark.parametrize("path", ["/health", "/notes", "/does-not-exist"])
def test_security_headers_on_every_response(client, path):
    response = client.get(path)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


@pytest.mark.parametrize("payload", [
    None, [], "text", {"title": "", "body": "x"}, {"title": "   ", "body": "x"},
    {"title": 5, "body": "x"}, {"title": "t"}, {"title": "t" * (MAX_TITLE + 1), "body": "x"},
])
def test_invalid_input_is_rejected(client, payload):
    response = client.post("/notes", json=payload) if payload is not None else client.post("/notes", data="not json")
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_sql_injection_payload_is_stored_as_data(client):
    payload = "x'); DROP TABLE notes; --"
    note_id = client.post("/notes", json={"title": payload, "body": "b"}).get_json()["id"]
    assert client.get(f"/notes/{note_id}").get_json()["title"] == payload
    assert client.get("/notes").status_code == 200  # table still exists


@pytest.mark.parametrize("path", ["/notes/abc", "/notes/1%20OR%201=1", "/notes/999"])
def test_bad_or_missing_ids_return_json_404(client, path):
    response = client.get(path)
    assert response.status_code == 404 and response.get_json() == {"error": "not found"}


def test_oversized_body_is_rejected(client):
    response = client.post("/notes", data="x" * (17 * 1024), content_type="application/json")
    assert response.status_code == 413


def test_wrong_method_returns_json_405(client):
    response = client.delete("/notes")
    assert response.status_code == 405 and response.get_json() == {"error": "method not allowed"}
