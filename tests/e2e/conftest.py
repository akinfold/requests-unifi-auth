"""Fixtures for live UniFi controller e2e tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple
from urllib.parse import urlparse

import pytest
import requests
import urllib3

from requests_unifi_auth import UnifiControllerAuth
from requests_unifi_auth import __version__ as PACKAGE_VERSION

from .diagnostics import DiagnosticsCollector

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

PROTECTED_GET_PATH = "/proxy/network/api/s/default/self"
SYSINFO_PATH = "/proxy/network/api/s/default/stat/sysinfo"
SYSTEM_PATH = "/api/system"


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def e2e_credentials() -> Optional[Tuple[str, str, str, bool]]:
    host = os.environ.get("UNIFI_E2E_HOST", "").strip()
    username = os.environ.get("UNIFI_E2E_USERNAME", "").strip()
    password = os.environ.get("UNIFI_E2E_PASSWORD", "").strip()
    if not host or not username or not password:
        return None
    verify_ssl = _env_flag("UNIFI_E2E_VERIFY_SSL", default=False)
    return host, username, password, verify_ssl


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "e2e: live tests against a real UniFi controller (LAN)"
    )


@pytest.fixture(scope="session")
def e2e_config() -> Tuple[str, str, str, bool]:
    creds = e2e_credentials()
    if creds is None:
        pytest.skip(
            "Set UNIFI_E2E_HOST, UNIFI_E2E_USERNAME, and UNIFI_E2E_PASSWORD to run live e2e"
        )
    return creds


@pytest.fixture(scope="session")
def diagnostics(e2e_config: Tuple[str, str, str, bool]) -> Iterator[DiagnosticsCollector]:
    host, _, _, _ = e2e_config
    collector = DiagnosticsCollector(controller_host=host)
    yield collector


@pytest.fixture(scope="session", autouse=True)
def _disable_insecure_warnings(e2e_config: Tuple[str, str, str, bool]) -> None:
    _, _, _, verify_ssl = e2e_config
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@pytest.fixture
def base_url(e2e_config: Tuple[str, str, str, bool]) -> str:
    host, _, _, _ = e2e_config
    if "://" in host:
        parsed = urlparse(host)
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{host}"


@pytest.fixture
def verify_ssl(e2e_config: Tuple[str, str, str, bool]) -> bool:
    return e2e_config[3]


@pytest.fixture
def auth(e2e_config: Tuple[str, str, str, bool]) -> UnifiControllerAuth:
    host, username, password, _ = e2e_config
    netloc = urlparse(host).netloc if "://" in host else host
    return UnifiControllerAuth(username, password, netloc)


@pytest.fixture
def session(auth: UnifiControllerAuth) -> Iterator[requests.Session]:
    s = requests.Session()
    s.auth = auth
    yield s
    s.close()


def probe_versions(
    session: requests.Session,
    base_url: str,
    verify_ssl: bool,
    diagnostics: DiagnosticsCollector,
) -> Dict[str, Optional[str]]:
    """Best-effort UniFi Network / OS version discovery (read-only)."""
    network_version: Optional[str] = None
    os_version: Optional[str] = None

    try:
        resp = session.get(f"{base_url}{SYSINFO_PATH}", verify=verify_ssl, timeout=30)
        diagnostics.record_response("probe sysinfo", resp)
        if resp.ok:
            payload = resp.json()
            if isinstance(payload, dict):
                data = payload.get("data") or payload
                if isinstance(data, list) and data:
                    data = data[0]
                if isinstance(data, dict):
                    for key in ("version", "network_version", "applicationVersion"):
                        if data.get(key):
                            network_version = str(data[key])
                            break
    except Exception as exc:  # noqa: BLE001 - probe must not fail the suite alone
        diagnostics.record_error("probe sysinfo", "GET", f"{base_url}{SYSINFO_PATH}", exc)
        diagnostics.notes.append(f"sysinfo probe failed: {type(exc).__name__}")

    try:
        resp = session.get(f"{base_url}{SYSTEM_PATH}", verify=verify_ssl, timeout=30)
        diagnostics.record_response("probe system", resp)
        if resp.ok:
            payload = resp.json()
            if isinstance(payload, dict):
                if payload.get("version"):
                    os_version = str(payload["version"])
                else:
                    device = payload.get("device")
                    if isinstance(device, dict) and device.get("version"):
                        os_version = str(device["version"])
    except Exception as exc:  # noqa: BLE001
        diagnostics.record_error("probe system", "GET", f"{base_url}{SYSTEM_PATH}", exc)
        diagnostics.notes.append(f"system probe failed: {type(exc).__name__}")

    diagnostics.network_version = network_version
    diagnostics.os_version = os_version
    return {"network_version": network_version, "os_version": os_version}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):  # type: ignore[no-untyped-def]
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return
    state = getattr(item.session.config, "_e2e_session_state", None)
    if not state or "e2e" not in item.keywords:
        return
    state["ran"] = True
    if report.failed:
        state["failed"] = True


def pytest_sessionstart(session: pytest.Session) -> None:
    session.config._e2e_session_state = {"failed": False, "versions": {}, "ran": False}  # type: ignore[attr-defined]


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    state = getattr(session.config, "_e2e_session_state", None)
    if not state or not state.get("ran"):
        return

    collector = getattr(session.config, "_e2e_diagnostics", None)
    if state.get("failed") or exitstatus != 0:
        if isinstance(collector, DiagnosticsCollector):
            path = collector.write()
            print(f"\n[e2e] Wrote redacted diagnostics to {path}")
            print("[e2e] Suggested GitHub issue body:\n")
            print(collector.issue_body())
        return

    versions = state.get("versions") or {}
    if not isinstance(versions, dict):
        return
    network = versions.get("network_version") or "unknown"
    os_ver = versions.get("os_version") or "unknown"
    try:
        from update_compatibility import update_compatibility_file

        path = update_compatibility_file(
            package_version=PACKAGE_VERSION,
            network_version=str(network),
            os_version=str(os_ver),
            notes="live e2e",
        )
        print(f"\n[e2e] Updated compatibility matrix: {path}")
        print("[e2e] Commit COMPATIBILITY.md when ready.")
    except Exception as exc:  # noqa: BLE001
        print(f"\n[e2e] Failed to update COMPATIBILITY.md: {exc}")


@pytest.fixture(scope="session", autouse=True)
def _publish_diagnostics(
    request: pytest.FixtureRequest,
    diagnostics: DiagnosticsCollector,
) -> Iterator[None]:
    request.config._e2e_diagnostics = diagnostics  # type: ignore[attr-defined]
    state = request.config._e2e_session_state  # type: ignore[attr-defined]
    yield
    state["versions"] = {
        "network_version": diagnostics.network_version,
        "os_version": diagnostics.os_version,
    }
