import pytest
import requests

from requests_unifi_auth import UnifiControllerAuth


@pytest.fixture
def auth():
    return UnifiControllerAuth("test_user", "test_pass", "ctrl.example")


def controller_response(cookie=None, token=None, url="https://ctrl.example/resource"):
    response = requests.Response()
    response.status_code = 200
    response.url = url
    if cookie is not None:
        response.cookies.set("session", cookie, domain="ctrl.example", path="/")
    if token is not None:
        response.headers["x-updated-csrf-token"] = token
    return response


def test_set_cookie_copies_response_jar(auth):
    response = controller_response(cookie="value")
    assert auth.set_cookie(response)
    assert auth._cookies.get("session") == "value"
    assert auth._cookies is not response.cookies
    response.cookies.set("session", "changed", domain="ctrl.example", path="/")
    assert auth._cookies.get("session") == "value"


def test_set_cookie_merges_response_jar(auth):
    auth.set_cookie(controller_response(cookie="old"))
    auth._cookies.set("other", "keep", domain="ctrl.example", path="/")
    assert auth.set_cookie(controller_response(cookie="new"))
    assert auth._cookies.get("session") == "new"
    assert auth._cookies.get("other") == "keep"


def test_set_cookie_empty_response_keeps_existing_state(auth):
    auth.set_cookie(controller_response(cookie="old"))
    assert not auth.set_cookie(controller_response())
    assert auth._cookies.get("session") == "old"


@pytest.mark.parametrize("method", ["set_cookie", "update_csrf_token"])
def test_manual_response_updates_reject_other_origins(auth, method):
    response = controller_response(
        cookie="foreign", token="foreign", url="https://other.example/"
    )
    assert not getattr(auth, method)(response)
    assert auth._cookies is None
    assert auth._csrf_token is None


def test_csrf_update_requires_header(auth):
    assert not auth.update_csrf_token(controller_response())
    assert auth._csrf_token is None
    assert auth.update_csrf_token(controller_response(token="first"))
    assert not auth.update_csrf_token(controller_response())
    assert auth._csrf_token == "first"
    assert auth.update_csrf_token(controller_response(token=""))
    assert auth._csrf_token is None


@pytest.mark.parametrize(
    "method", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
)
def test_prepare_request_adds_csrf_only_for_mutating_methods(auth, method):
    auth.set_cookie(controller_response(cookie="value", token="csrf"))
    request = requests.Request(
        method, "https://ctrl.example/resource", auth=auth
    ).prepare()
    assert request.headers["Cookie"] == "session=value"
    assert ("X-CSRF-Token" in request.headers) == (
        method not in {"GET", "HEAD", "OPTIONS"}
    )


def test_prepare_request_without_state(auth):
    request = requests.Request(
        "POST", "https://ctrl.example/resource", auth=auth
    ).prepare()
    assert "Cookie" not in request.headers
    assert "X-CSRF-Token" not in request.headers
    assert len(request.hooks["response"]) == 1


def test_prepare_unprepared_request_copies_cookie_state(auth):
    auth.set_cookie(controller_response(cookie="value"))
    request = requests.Request(
        "POST", "https://ctrl.example/resource", cookies={"other": "keep"}
    )
    auth.prepare_request(request)
    assert request.cookies is not auth._cookies
    assert request.cookies.get("session") == "value"
    assert request.cookies.get("other") == "keep"


def test_non_401_updates_state_and_returns_same_response(auth):
    response = controller_response(cookie="value", token="rotated")
    assert auth.handle_401(response) is response
    assert auth._csrf_token == "rotated"


@pytest.mark.parametrize("status", [200, 401])
def test_foreign_response_never_authorizes(auth, status):
    response = controller_response(token="foreign", url="https://other.example/")
    response.status_code = status
    assert auth.handle_401(response) is response
    assert not auth.authorize(response)
    assert auth._csrf_token is None
