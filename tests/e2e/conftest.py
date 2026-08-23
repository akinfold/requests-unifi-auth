"""Fixtures for live UniFi controller e2e tests."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple
from urllib.parse import urlparse

import pytest
import requests
import urllib3

from requests_unifi_auth import UnifiControllerAuth
from requests_unifi_auth import __version__ as PACKAGE_VERSION

from .config import E2ESettings, load_e2e_settings, missing_config_message
from .diagnostics import DiagnosticsCollector

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

PROTECTED_GET_PATH = "/proxy/network/api/s/default/self"
SYSINFO_PATH = "/proxy/network/api/s/default/stat/sysinfo"
SYSTEM_PATH = "/api/system"

# Session password kept off fixture values that pytest may print.
_PASSWORD_BY_CONFIG_ID: Dict[int, str] = {}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "e2e: live tests against a real UniFi controller (LAN)"
    )


@pytest.fixture(scope="session")
def e2e_config() -> E2ESettings:
    loaded = load_e2e_settings()
    if loaded is None:
        pytest.skip(missing_config_message())
    settings, password = loaded
    _PASSWORD_BY_CONFIG_ID[id(settings)] = password
    return settings


@pytest.fixture(scope="session")
def e2e_password(e2e_config: E2ESettings) -> str:
    password = _PASSWORD_BY_CONFIG_ID.get(id(e2e_config))
    if not password:
        pytest.skip(missing_config_message())
    return password


@pytest.fixture(scope="session")
def diagnostics(e2e_config: E2ESettings) -> Iterator[DiagnosticsCollector]:
    collector = DiagnosticsCollector(controller_host=e2e_config.host)
    yield collector


@pytest.fixture(scope="session", autouse=True)
def _disable_insecure_warnings(e2e_config: E2ESettings) -> None:
    if not e2e_config.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@pytest.fixture
def base_url(e2e_config: E2ESettings) -> str:
    host = e2e_config.host
    if "://" in host:
        parsed = urlparse(host)
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{host}"


@pytest.fixture
def verify_ssl(e2e_config: E2ESettings) -> bool:
    return e2e_config.verify_ssl


@pytest.fixture
def auth(e2e_config: E2ESettings, e2e_password: str) -> UnifiControllerAuth:
    host = e2e_config.host
    netloc = urlparse(host).netloc if "://" in host else host
    return UnifiControllerAuth(e2e_config.username, e2e_password, netloc)


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
    state = getattr(request.config, "_e2e_session_state", None)
    if state is None:
        state = {"failed": False, "versions": {}, "ran": False}
        request.config._e2e_session_state = state  # type: ignore[attr-defined]
    yield
    state["versions"] = {
        "network_version": diagnostics.network_version,
        "os_version": diagnostics.os_version,
    }
