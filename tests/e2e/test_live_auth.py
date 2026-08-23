"""Live authentication scenarios against a real UniFi controller."""

from __future__ import annotations

import pytest
import requests

from requests_unifi_auth import UnifiControllerAuth

from .conftest import PROTECTED_GET_PATH, probe_versions
from .diagnostics import DiagnosticsCollector

pytestmark = pytest.mark.e2e


def test_login_on_401_then_authenticated_get(
    session: requests.Session,
    auth: UnifiControllerAuth,
    base_url: str,
    verify_ssl: bool,
    diagnostics: DiagnosticsCollector,
) -> None:
    url = f"{base_url}{PROTECTED_GET_PATH}"
    try:
        resp = session.get(url, verify=verify_ssl, timeout=30)
        diagnostics.record_response("authenticated GET after possible 401 login", resp)
    except Exception as exc:  # noqa: BLE001
        diagnostics.record_error("authenticated GET", "GET", url, exc)
        raise

    assert resp.status_code < 400, (
        f"expected success after auth, got {resp.status_code}"
    )
    assert auth._cookies is not None
    diagnostics.notes.append("login-on-401 path produced an authenticated response")

    versions = probe_versions(session, base_url, verify_ssl, diagnostics)
    diagnostics.notes.append(
        f"probed network={versions.get('network_version')!r} os={versions.get('os_version')!r}"
    )


def test_session_reuses_cookies_without_relogin(
    session: requests.Session,
    auth: UnifiControllerAuth,
    base_url: str,
    verify_ssl: bool,
    diagnostics: DiagnosticsCollector,
) -> None:
    url = f"{base_url}{PROTECTED_GET_PATH}"
    first = session.get(url, verify=verify_ssl, timeout=30)
    diagnostics.record_response("first authenticated GET", first)
    assert first.status_code < 400
    assert auth._cookies is not None

    cookies_before = list(auth._cookies)

    second = session.get(url, verify=verify_ssl, timeout=30)
    diagnostics.record_response("second authenticated GET", second)
    assert second.status_code < 400
    assert list(auth._cookies) == cookies_before
    diagnostics.notes.append("cookie jar unchanged across consecutive GETs")


def test_bad_password_does_not_authenticate(
    e2e_config,
    base_url: str,
    verify_ssl: bool,
    diagnostics: DiagnosticsCollector,
) -> None:
    host = e2e_config.host
    username = e2e_config.username
    netloc = host.split("://", 1)[-1] if "://" in host else host
    bad_auth = UnifiControllerAuth(username, "definitely-wrong-password", netloc)
    s = requests.Session()
    s.auth = bad_auth
    url = f"{base_url}{PROTECTED_GET_PATH}"
    try:
        resp = s.get(url, verify=verify_ssl, timeout=30)
        diagnostics.record_response("GET with bad password", resp)
    finally:
        s.close()

    assert resp.status_code == 401
    assert bad_auth._cookies is None
    diagnostics.notes.append("bad password left session unauthenticated")


def test_csrf_token_attached_to_unsafe_methods_when_present(
    session: requests.Session,
    auth: UnifiControllerAuth,
    base_url: str,
    verify_ssl: bool,
    diagnostics: DiagnosticsCollector,
) -> None:
    url = f"{base_url}{PROTECTED_GET_PATH}"
    resp = session.get(url, verify=verify_ssl, timeout=30)
    diagnostics.record_response("GET before CSRF check", resp)
    assert resp.status_code < 400

    rotated = resp.headers.get("x-updated-csrf-token")
    if rotated:
        diagnostics.notes.append("controller returned x-updated-csrf-token on GET")
        assert auth._csrf_token == rotated

    prepared = requests.Request("POST", f"{base_url}/api/example").prepare()
    auth.prepare_request(prepared)

    if auth._csrf_token:
        assert prepared.headers.get("X-CSRF-Token") == auth._csrf_token
        diagnostics.notes.append("X-CSRF-Token attached to prepared POST")
    else:
        assert "X-CSRF-Token" not in prepared.headers
        diagnostics.notes.append(
            "no CSRF token after login/GET; POST correctly omits X-CSRF-Token"
        )
