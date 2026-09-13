"""Local regression tests for live e2e support helpers."""

from __future__ import annotations

import json
import os
import pty
import select
import stat
import subprocess
import sys
import termios
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Optional

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from e2e.config import E2ESettings, parse_dotenv  # noqa: E402
from e2e import conftest as e2e_conftest  # noqa: E402
from e2e.diagnostics import (  # noqa: E402
    DiagnosticsCollector,
    _sanitize_error,
)
from e2e.gating import REQUIRED_E2E_TESTS, e2e_run_is_complete  # noqa: E402
from e2e.write_probe import run_disposable_write_round_trip  # noqa: E402


def _complete_gate_state() -> Dict[str, object]:
    phases = {"setup": "passed", "call": "passed", "teardown": "passed"}
    return {
        "failed": False,
        "write_enabled": True,
        "phase_outcomes": {name: dict(phases) for name in REQUIRED_E2E_TESTS},
    }


def test_dotenv_round_trips_special_values() -> None:
    values = {
        "UNIFI_E2E_USERNAME": "  user 'quoted'  ",
        "UNIFI_E2E_PASSWORD": r"  p# $ = \\ ' \"  ",
        "UNICODE": "Привет мир",
    }
    encoded = "\n".join(
        f"{key}='{value.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))}'"
        for key, value in values.items()
    )
    assert parse_dotenv(encoded) == values


def test_dotenv_accepts_whitespace_around_assignment() -> None:
    assert parse_dotenv('UNIFI_E2E_PASSWORD = "synthetic-secret"') == {
        "UNIFI_E2E_PASSWORD": "synthetic-secret"
    }


def test_pytest_failure_output_does_not_show_assertion_secrets(
    tmp_path: Path,
) -> None:
    secrets = (
        "synthetic-cookie-secret-for-output-test",
        "synthetic-current-csrf-token-for-output-test",
        "synthetic-rotated-csrf-token-for-output-test",
    )
    test_file = tmp_path / "test_failure_output.py"
    test_file.write_text(
        "from e2e.safe_assertions import assert_secret_condition\n\n"
        "def test_cookie_failure():\n"
        f"    cookie_state = {secrets[0]!r}\n"
        "    assert_secret_condition(\n"
        "        cookie_state is None,\n"
        '        "bad password unexpectedly populated the cookie state",\n'
        "    )\n\n"
        "def test_csrf_failure():\n"
        f"    current_token = {secrets[1]!r}\n"
        f"    rotated_token = {secrets[2]!r}\n"
        "    assert_secret_condition(\n"
        "        current_token == rotated_token,\n"
        '        "authentication state did not retain the rotated CSRF token",\n'
        "    )\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    pythonpath = [str(REPO_ROOT / "tests")]
    if existing_pythonpath := env.get("PYTHONPATH"):
        pythonpath.append(existing_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(REPO_ROOT / "pyproject.toml"),
            "-q",
            str(test_file),
        ],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1
    for secret in secrets:
        assert secret not in output
    assert "bad password unexpectedly populated the cookie state" in output
    assert "authentication state did not retain the rotated CSRF token" in output


def _read_until(fd: int, expected: bytes, output: bytearray) -> None:
    deadline = time.monotonic() + 10
    while expected not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"helper did not print expected prompt: {expected!r}")
        ready, _, _ = select.select([fd], [], [], remaining)
        if ready:
            chunk = os.read(fd, 4096)
            if not chunk:
                raise EOFError(f"helper exited before prompt: {expected!r}")
            output.extend(chunk)


def _run_config_helper(config_path: Path, password: str) -> bytes:
    master_fd, slave_fd = pty.openpty()
    env = os.environ.copy()
    env["UNIFI_E2E_CONFIG"] = str(config_path)
    process = subprocess.Popen(
        ["bash", str(REPO_ROOT / "scripts" / "init_e2e_config.sh")],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)
    output = bytearray()
    conversations = [
        (b"Controller host", b"ctrl.example\n", False),
        (b"Username", b"synthetic-user\n", False),
        (b"Password (", password.encode() + b"\n", True),
        (b"Confirm password", password.encode() + b"\n", True),
        (b"Verify TLS", b"true\n", False),
        (b"Enable disposable write", b"false\n", False),
    ]
    try:
        for prompt, answer, hidden in conversations:
            _read_until(master_fd, prompt, output)
            if hidden:
                deadline = time.monotonic() + 2
                while termios.tcgetattr(master_fd)[3] & termios.ECHO:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            "password prompt did not disable terminal echo"
                        )
                    time.sleep(0.01)
            os.write(master_fd, answer)
        _read_until(master_fd, b"Wrote ", output)
        return_code = process.wait(timeout=10)
        while True:
            ready, _, _ = select.select([master_fd], [], [], 0)
            if not ready:
                break
            try:
                chunk = os.read(master_fd, 4096)
                if not chunk:
                    break
                output.extend(chunk)
            except OSError:
                break
    finally:
        os.close(master_fd)
        if process.poll() is None:
            process.kill()
            process.wait()
    assert return_code == 0, output.decode(errors="replace")
    return bytes(output)


def test_config_helper_preserves_password_spaces_and_parent_mode(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "shared-config"
    parent.mkdir(mode=0o750)
    parent.chmod(0o750)
    config_path = parent / "e2e.env"
    password = "  p# $ = \\ ' synthetic  "

    output = _run_config_helper(config_path, password)

    assert stat.S_IMODE(parent.stat().st_mode) == 0o750
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert (
        parse_dotenv(config_path.read_text(encoding="utf-8"))["UNIFI_E2E_PASSWORD"]
        == password
    )
    assert password.encode() not in output


@pytest.mark.parametrize(
    "secret_text",
    [
        "https://alice:two words@example.test/x",
        "https://alice:pa@ss@example.test/x",
        "https://alice:line\nbreak@example.test/x",
        "https://example.test/x?token=token-secret&safe=yes",
        "Authorization: bearer-secret",
        "Authorization: Bearer bearer-secret",
        "Cookie=session-secret",
    ],
)
def test_diagnostic_text_redacts_secret_carriers(secret_text: str) -> None:
    sanitized = _sanitize_error(secret_text)
    assert "alice" not in sanitized
    assert "two words" not in sanitized
    assert "pa@ss" not in sanitized
    assert "line break" not in sanitized
    assert "token-secret" not in sanitized
    assert "bearer-secret" not in sanitized
    assert "session-secret" not in sanitized


def test_diagnostics_never_persists_exception_or_response_error_text() -> None:
    collector = DiagnosticsCollector(
        controller_host="https://user:host-secret@example.test"
    )
    collector.record_error(
        "request",
        "GET",
        "https://example.test/api",
        RuntimeError("failed https://alice:error-secret@example.test/x"),
    )
    response = _response(
        "GET", "https://example.test/api", 500, {"meta": {"rc": "error"}}
    )
    collector.record_response(
        "response",
        response,
        error="Authorization: response-secret",
    )

    rendered = collector.render_markdown()

    for secret in ("host-secret", "alice", "error-secret", "response-secret"):
        assert secret not in rendered
    assert "RuntimeError" in rendered
    assert "Controller host: redacted" in rendered


def test_compatibility_gate_requires_every_successful_phase() -> None:
    state = _complete_gate_state()
    collected = set(REQUIRED_E2E_TESTS) | {"test_optional_probe"}
    assert e2e_run_is_complete(state, collected, 0)

    for phase in ("setup", "call", "teardown"):
        broken = _complete_gate_state()
        test_name = next(iter(REQUIRED_E2E_TESTS))
        broken["phase_outcomes"][test_name].pop(phase)  # type: ignore[index,union-attr]
        assert not e2e_run_is_complete(broken, collected, 0)


def test_compatibility_gate_rejects_missing_skip_failure_and_write_disabled() -> None:
    state = _complete_gate_state()
    collected = set(REQUIRED_E2E_TESTS)
    assert not e2e_run_is_complete(state, {next(iter(collected))}, 0)

    test_name = next(iter(REQUIRED_E2E_TESTS))
    state["phase_outcomes"][test_name]["call"] = "skipped"  # type: ignore[index]
    assert not e2e_run_is_complete(state, collected, 0)

    state = _complete_gate_state()
    state["failed"] = True
    assert not e2e_run_is_complete(state, collected, 0)

    state = _complete_gate_state()
    state["write_enabled"] = False
    assert not e2e_run_is_complete(state, collected, 0)

    assert not e2e_run_is_complete(_complete_gate_state(), collected, 1)
    assert not e2e_run_is_complete({}, collected, 0)


def test_diagnostics_fixture_publishes_write_flag_and_versions() -> None:
    state = _complete_gate_state()
    state.update({"versions": {}, "ran": False})
    request = SimpleNamespace(config=SimpleNamespace(_e2e_session_state=state))
    collector = DiagnosticsCollector()
    collector.network_version = "10.0"
    collector.os_version = "5.0"
    settings = E2ESettings("ctrl.example", "synthetic-user", enable_write=True)

    fixture = e2e_conftest._publish_diagnostics.__wrapped__(
        request, collector, settings
    )
    next(fixture)
    assert state["write_enabled"] is True
    with pytest.raises(StopIteration):
        next(fixture)
    assert state["versions"] == {"network_version": "10.0", "os_version": "5.0"}


def _response(
    method: str,
    url: str,
    status: int,
    payload: Optional[Dict[str, object]] = None,
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.request = requests.Request(method, url).prepare()
    response.headers["Content-Type"] = "application/json"
    response._content = b"" if payload is None else json.dumps(payload).encode()
    return response


class FakeWriteSession:
    def __init__(
        self,
        *,
        create_status: int = 200,
        raise_after_create: bool = False,
        reject_delete: bool = False,
        invalid_cleanup_inventory: bool = False,
        idless_cleanup_inventory: bool = False,
        unrelated_create_response: bool = False,
        unrelated_update_response: bool = False,
    ) -> None:
        self.create_status = create_status
        self.raise_after_create = raise_after_create
        self.reject_delete = reject_delete
        self.invalid_cleanup_inventory = invalid_cleanup_inventory
        self.idless_cleanup_inventory = idless_cleanup_inventory
        self.unrelated_create_response = unrelated_create_response
        self.unrelated_update_response = unrelated_update_response
        self.delete_attempted = False
        self.objects: Dict[str, Dict[str, object]] = (
            {"preexisting-id": {"_id": "preexisting-id", "name": "unrelated-group"}}
            if unrelated_create_response or unrelated_update_response
            else {}
        )
        self.methods = []

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        self.methods.append(method)
        payload = kwargs.get("json") or {}
        if method == "POST":
            object_id = "synthetic-id"
            self.objects[object_id] = dict(payload, _id=object_id)
            if self.raise_after_create:
                raise requests.Timeout("synthetic uncertain create")
            response_data = [self.objects[object_id]]
            if self.unrelated_create_response:
                response_data.insert(0, self.objects["preexisting-id"])
            return _response(
                method,
                url,
                self.create_status,
                {"meta": {"rc": "ok"}, "data": response_data},
            )
        if method == "PUT":
            object_id = url.rsplit("/", 1)[-1]
            self.objects[object_id] = dict(payload, _id=object_id)
            response_data = [self.objects[object_id]]
            if self.unrelated_update_response:
                response_data.insert(0, self.objects["preexisting-id"])
            return _response(
                method,
                url,
                200,
                {"meta": {"rc": "ok"}, "data": response_data},
            )
        if method == "DELETE":
            self.delete_attempted = True
            object_id = url.rsplit("/", 1)[-1]
            if self.invalid_cleanup_inventory or self.idless_cleanup_inventory:
                return _response(method, url, 200, {"meta": {"rc": "ok"}, "data": []})
            if self.reject_delete:
                return _response(
                    method,
                    url,
                    200,
                    {"meta": {"rc": "error"}, "data": []},
                )
            self.objects.pop(object_id, None)
            return _response(method, url, 200, {"meta": {"rc": "ok"}, "data": []})
        if method == "GET":
            if self.invalid_cleanup_inventory and self.delete_attempted:
                return _response(method, url, 200, {"meta": {"rc": "ok"}})
            if self.idless_cleanup_inventory and self.delete_attempted:
                items = []
                for item in self.objects.values():
                    items.append(
                        {key: value for key, value in item.items() if key != "_id"}
                    )
                return _response(
                    method,
                    url,
                    200,
                    {"meta": {"rc": "ok"}, "data": items},
                )
            return _response(
                method,
                url,
                200,
                {"meta": {"rc": "ok"}, "data": list(self.objects.values())},
            )
        raise AssertionError(f"unexpected method {method}")


def _run_write_probe(session: FakeWriteSession) -> None:
    run_disposable_write_round_trip(
        session,  # type: ignore[arg-type]
        DiagnosticsCollector(),
        "https://ctrl.example",
        True,
        "requests-unifi-auth-e2e-synthetic",
    )


def test_disposable_write_probe_updates_and_verifies_cleanup() -> None:
    session = FakeWriteSession()
    _run_write_probe(session)
    assert session.objects == {}
    assert {"POST", "PUT", "GET", "DELETE"}.issubset(session.methods)


def test_disposable_write_probe_cleans_up_after_http_error() -> None:
    session = FakeWriteSession(create_status=500)
    with pytest.raises(AssertionError, match="unexpected HTTP status"):
        _run_write_probe(session)
    assert session.objects == {}
    assert "DELETE" in session.methods


def test_disposable_write_probe_does_not_delete_unrelated_create_response_object():
    session = FakeWriteSession(
        create_status=500,
        unrelated_create_response=True,
    )
    with pytest.raises(AssertionError, match="unexpected HTTP status"):
        _run_write_probe(session)
    assert set(session.objects) == {"preexisting-id"}


def test_disposable_write_probe_does_not_delete_unrelated_update_response_object():
    session = FakeWriteSession(unrelated_update_response=True)
    _run_write_probe(session)
    assert set(session.objects) == {"preexisting-id"}


def test_disposable_write_probe_recovers_uncertain_creation() -> None:
    session = FakeWriteSession(raise_after_create=True)
    with pytest.raises(requests.Timeout):
        _run_write_probe(session)
    assert session.objects == {}
    assert "DELETE" in session.methods


def test_disposable_write_probe_rejects_unverified_cleanup() -> None:
    session = FakeWriteSession(reject_delete=True)
    with pytest.raises(AssertionError, match="cleanup"):
        _run_write_probe(session)
    assert session.objects


def test_disposable_write_probe_rejects_invalid_cleanup_inventory() -> None:
    session = FakeWriteSession(invalid_cleanup_inventory=True)
    with pytest.raises(AssertionError, match="cleanup"):
        _run_write_probe(session)
    assert session.objects


def test_disposable_write_probe_rejects_idless_matching_object() -> None:
    session = FakeWriteSession(idless_cleanup_inventory=True)
    with pytest.raises(AssertionError, match="cleanup"):
        _run_write_probe(session)
    assert session.objects
