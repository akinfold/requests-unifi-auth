"""Pure completion gate for compatibility publication."""

from __future__ import annotations

from typing import Any

REQUIRED_READ_ONLY_E2E_TESTS = {
    "test_login_on_401_then_authenticated_get",
    "test_session_reuses_cookies_without_relogin",
    "test_bad_password_does_not_authenticate",
    "test_csrf_token_attached_to_unsafe_methods_when_present",
}
WRITE_E2E_TEST = "test_disposable_write_round_trip"
REQUIRED_E2E_TESTS = REQUIRED_READ_ONLY_E2E_TESTS | {
    WRITE_E2E_TEST,
}


def e2e_run_is_complete(
    state: dict[str, Any], collected_names: set[str], exitstatus: int
) -> bool:
    """Return true after read-only checks and any enabled write check pass."""
    if exitstatus != 0 or state.get("failed"):
        return False
    if not REQUIRED_E2E_TESTS.issubset(collected_names):
        return False
    outcomes = state.get("phase_outcomes")
    if not isinstance(outcomes, dict):
        return False
    required_tests = set(REQUIRED_READ_ONLY_E2E_TESTS)
    if state.get("write_enabled"):
        required_tests.add(WRITE_E2E_TEST)
    return all(
        outcomes.get(test_name)
        == {"setup": "passed", "call": "passed", "teardown": "passed"}
        for test_name in required_tests
    )
