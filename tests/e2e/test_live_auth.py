"""Live authentication scenarios against a real UniFi controller."""

from __future__ import annotations

import uuid

import pytest
import requests

from requests_unifi_auth import UnifiControllerAuth

from .conftest import PROTECTED_GET_PATH, probe_versions
from .diagnostics import DiagnosticsCollector
from .safe_assertions import assert_secret_condition
from .write_probe import run_disposable_write_round_trip

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
    assert_secret_condition(
        auth._cookies is not None,
        "authenticated response did not populate the cookie state",
    )
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
    assert_secret_condition(
        auth._cookies is not None,
        "first authenticated response did not populate the cookie state",
    )

    login_generation = auth._generation
    assert login_generation > 0

    second = session.get(url, verify=verify_ssl, timeout=30)
    diagnostics.record_response("second authenticated GET", second)
    assert second.status_code < 400
    assert auth._generation == login_generation
    assert_secret_condition(
        auth._cookies is not None,
        "second authenticated response did not retain the cookie state",
    )
    diagnostics.notes.append("second GET reused authentication without another login")


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
    assert_secret_condition(
        bad_auth._cookies is None,
        "bad password unexpectedly populated the cookie state",
    )
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
        assert_secret_condition(
            auth._csrf_token == rotated,
            "authentication state did not retain the rotated CSRF token",
        )

    prepared = requests.Request("POST", f"{base_url}/api/example").prepare()
    auth.prepare_request(prepared)

    if auth._csrf_token:
        assert_secret_condition(
            prepared.headers.get("X-CSRF-Token") == auth._csrf_token,
            "prepared POST did not carry the current CSRF token",
        )
        diagnostics.notes.append("X-CSRF-Token attached to prepared POST")
    else:
        assert_secret_condition(
            "X-CSRF-Token" not in prepared.headers,
            "prepared POST unexpectedly carried a CSRF token",
        )
        diagnostics.notes.append(
            "no CSRF token after login/GET; POST correctly omits X-CSRF-Token"
        )


def test_disposable_write_round_trip(
    session: requests.Session,
    e2e_config,
    base_url: str,
    verify_ssl: bool,
    diagnostics: DiagnosticsCollector,
) -> None:
    """Exercise verified create/update/delete only with explicit opt-in."""
    if not e2e_config.enable_write:
        pytest.skip("set UNIFI_E2E_ENABLE_WRITE=true to enable disposable writes")
    name = f"requests-unifi-auth-e2e-{uuid.uuid4().hex}"
    run_disposable_write_round_trip(
        session,
        diagnostics,
        base_url,
        verify_ssl,
        name,
    )
