"""Pure completion gate for compatibility publication."""

from __future__ import annotations

from typing import Any

REQUIRED_E2E_TESTS = {
    "test_login_on_401_then_authenticated_get",
    "test_session_reuses_cookies_without_relogin",
    "test_bad_password_does_not_authenticate",
    "test_csrf_token_attached_to_unsafe_methods_when_present",
    "test_disposable_write_round_trip",
}


def e2e_run_is_complete(
    state: dict[str, Any], collected_names: set[str], exitstatus: int
) -> bool:
    """Return true only after every phase of every required scenario passes."""
    if exitstatus != 0 or state.get("failed"):
        return False
    if not REQUIRED_E2E_TESTS.issubset(collected_names):
        return False
    if not state.get("write_enabled"):
        return False
    outcomes = state.get("phase_outcomes")
    if not isinstance(outcomes, dict):
        return False
    return all(
        outcomes.get(test_name)
        == {"setup": "passed", "call": "passed", "teardown": "passed"}
        for test_name in REQUIRED_E2E_TESTS
    )
