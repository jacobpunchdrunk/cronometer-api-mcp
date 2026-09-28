"""Session handling tests for CronometerClient, against a mocked HTTP layer."""

import json

import httpx
import pytest

from cronometer_api_mcp.client import (
    BASE_URL,
    SESSION_MAX_AGE_S,
    CronometerClient,
    CronometerError,
)


@pytest.fixture(autouse=True)
def _creds(monkeypatch):
    monkeypatch.setenv("CRONOMETER_USERNAME", "user@example.com")
    monkeypatch.setenv("CRONOMETER_PASSWORD", "hunter2")


def make_client(responses: dict[str, list]) -> tuple[CronometerClient, list[str]]:
    """Build a client whose endpoints answer from queued responses.

    responses maps a path to a list of (status, body) tuples, consumed in order;
    the last one repeats. /api/v2/login succeeds by default.
    """
    calls: list[str] = []
    logins = iter(range(1, 100))

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(path)
        if path == "/api/v2/login" and path not in responses:
            n = next(logins)
            return httpx.Response(
                200, json={"result": "SUCCESS", "id": 1, "sessionKey": f"tok-{n}"}
            )
        queue = responses[path]
        status, body = queue.pop(0) if len(queue) > 1 else queue[0]
        return httpx.Response(status, content=json.dumps(body))

    client = CronometerClient()
    client._http = httpx.Client(
        base_url=BASE_URL, transport=httpx.MockTransport(handler)
    )
    return client, calls


def test_live_session_logs_in_once():
    client, calls = make_client({"/api/v2/get_diary": [(200, {"diary": []})]})
    client.get_diary()
    client.get_diary()
    assert calls.count("/api/v2/login") == 1


def test_read_missing_key_relogs_and_retries():
    client, calls = make_client(
        {"/api/v2/get_diary": [(200, {}), (200, {"diary": [{"servingId": 7}]})]}
    )
    data = client.get_diary()
    assert data == {"diary": [{"servingId": 7}]}
    assert calls.count("/api/v2/login") == 2
    assert client._token == "tok-2"


def test_read_missing_key_twice_returns_without_looping():
    client, calls = make_client({"/api/v2/find_food": [(200, {})]})
    assert client.search_food("zzz") == []
    assert calls.count("/api/v2/login") == 2
    assert calls.count("/api/v2/find_food") == 2


def test_old_session_relogs_before_request():
    client, calls = make_client({"/api/v2/get_diary": [(200, {"diary": []})]})
    client.get_diary()
    client._logged_in_at -= SESSION_MAX_AGE_S + 1
    client.get_diary()
    assert calls == [
        "/api/v2/login",
        "/api/v2/get_diary",
        "/api/v2/login",
        "/api/v2/get_diary",
    ]


def test_unconfirmed_custom_food_relogs_without_retry():
    client, calls = make_client({"/api/v2/add_food": [(200, {})]})
    with pytest.raises(CronometerError, match="not retried"):
        client.create_custom_food("Test", calories=100, protein_g=1, fat_g=1, carbs_g=1)
    assert calls.count("/api/v2/add_food") == 1
    assert calls.count("/api/v2/login") == 2


def test_rejected_login_names_credentials():
    client, _ = make_client({"/api/v2/login": [(401, {"error": "bad"})]})
    with pytest.raises(CronometerError, match="CRONOMETER_USERNAME"):
        client.get_diary()


def test_401_relogs_and_retries_once():
    client, calls = make_client(
        {"/api/v2/get_diary": [(401, {}), (200, {"diary": []})]}
    )
    assert client.get_diary() == {"diary": []}
    assert calls.count("/api/v2/login") == 2
