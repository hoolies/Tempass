"""Behavior for one-time passwords."""

import html
import sqlite3
import threading
import time
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from tempass.app import PASSWORD_TTL_SECONDS, consume_password, database_path, generate_password, init_db, store_password


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TEMPASS_DB", str(tmp_path / "tempass.db"))
    monkeypatch.setenv("TEMPASS_API_KEY", "test-key")
    from tempass.app import app

    with TestClient(app) as test_client:
        yield test_client


def test_database_path_ignores_working_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("TEMPASS_DB", raising=False)
    monkeypatch.chdir(tmp_path)
    assert database_path() != tmp_path / "tempass.db"
    assert database_path().name == "tempass.db"


def test_password_includes_each_requested_class():
    password = generate_password(length=14, complexity=4)
    assert len(password) == 14
    assert any(character.islower() for character in password)
    assert any(character.isupper() for character in password)
    assert any(character.isdigit() for character in password)
    assert any(character in "!@#$%^&*-_=+" for character in password)


def test_generate_requires_the_api_key(client):
    missing = client.post("/generate")
    wrong = client.post("/generate", headers={"X-API-Key": "nope"})
    assert missing.status_code == 401
    assert wrong.status_code == 401


def test_generate_returns_the_password_for_the_caller(client):
    response = client.post("/generate", headers={"X-API-Key": "test-key"})
    body = response.json()
    assert response.status_code == 200
    assert body["reveal_path"] == f"/password/{body['token']}"
    assert len(body["password"]) == 14
    assert body["expires_at"] > int(time.time())


def test_unconfigured_api_key_rejects_generation(client, monkeypatch):
    monkeypatch.setenv("TEMPASS_API_KEY", "")
    response = client.post("/generate", headers={"X-API-Key": "test-key"})
    assert response.status_code == 401


def test_get_does_not_reveal_or_delete(client):
    created = client.post("/generate", headers={"X-API-Key": "test-key"}).json()
    preview = client.get(created["reveal_path"])
    assert preview.status_code == 200
    assert created["password"] not in preview.text
    assert "Show password" in preview.text
    revealed = client.post(created["reveal_path"])
    assert revealed.status_code == 200
    assert html.escape(created["password"]) in revealed.text


def test_second_reveal_is_a_miss(client):
    created = client.post("/generate", headers={"X-API-Key": "test-key"}).json()
    assert client.post(created["reveal_path"]).status_code == 200
    missed = client.post(created["reveal_path"])
    assert missed.status_code == 404
    assert created["password"] not in missed.text
    assert "no longer available" in missed.text


def test_expired_token_is_a_miss(client):
    init_db()
    created_at = int(time.time()) - PASSWORD_TTL_SECONDS - 1
    with sqlite3.connect(database_path()) as connection:
        connection.execute(
            "INSERT INTO tempass (token, password, created_at) VALUES (?, ?, ?)",
            ("old-token", "secret-value", created_at),
        )
    missed = client.post("/password/old-token")
    assert missed.status_code == 404
    assert "secret-value" not in missed.text


def test_token_lookup_is_parameterized(client):
    created = client.post("/generate", headers={"X-API-Key": "test-key"}).json()
    missed = client.post("/password/" + quote("' OR 1=1 --", safe=""))
    assert missed.status_code == 404
    revealed = client.post(created["reveal_path"])
    assert revealed.status_code == 200
    assert html.escape(created["password"]) in revealed.text


def test_only_one_reveal_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("TEMPASS_DB", str(tmp_path / "race.db"))
    init_db()
    assert store_password("tok", "pw", int(time.time()))
    results: list[str | None] = []
    barrier = threading.Barrier(2)

    def reveal() -> None:
        barrier.wait()
        results.append(consume_password("tok"))

    threads = [threading.Thread(target=reveal) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results, key=lambda value: value is None) == ["pw", None]


def test_admin_route_is_absent(client):
    assert client.get("/admin").status_code == 404
