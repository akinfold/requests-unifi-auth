"""Disposable live write probe with verified cleanup."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Set
from urllib.parse import quote

import requests

from .diagnostics import DiagnosticsCollector

WRITE_COLLECTION_PATH = "/proxy/network/api/s/default/rest/usergroup"


def _response_payload(response: requests.Response) -> Optional[Dict[str, Any]]:
    if not response.content:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _object_ids(
    payload: Optional[Dict[str, Any]], names: Optional[Set[str]] = None
) -> Set[str]:
    if payload is None:
        return set()
    data = payload.get("data")
    if not isinstance(data, list):
        return set()
    object_ids = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        if names is not None and item.get("name") not in names:
            continue
        object_id = item.get("_id") or item.get("id")
        if names is not None and not object_id:
            raise AssertionError("a matching disposable object has no identifier")
        if object_id:
            object_ids.add(str(object_id))
    return object_ids


def _assert_application_success(
    response: requests.Response,
    payload: Optional[Dict[str, Any]],
    operation: str,
) -> None:
    if not 200 <= response.status_code < 300:
        raise AssertionError(
            f"{operation} returned unexpected HTTP status {response.status_code}"
        )
    if payload is None and response.content:
        raise AssertionError(f"{operation} returned a non-JSON response")
    meta = payload.get("meta") if payload is not None else None
    if isinstance(meta, dict) and meta.get("rc") not in (None, "ok"):
        raise AssertionError(f"{operation} returned an application-level error")


def _recorded_request(
    session: requests.Session,
    diagnostics: DiagnosticsCollector,
    method: str,
    url: str,
    *,
    verify_ssl: bool,
    label: str,
    json: Optional[Dict[str, Any]] = None,
) -> requests.Response:
    response = session.request(
        method,
        url,
        json=json,
        verify=verify_ssl,
        timeout=30,
    )
    diagnostics.record_response(label, response)
    return response


def _matching_object_ids(
    session: requests.Session,
    diagnostics: DiagnosticsCollector,
    collection_url: str,
    names: Set[str],
    verify_ssl: bool,
    label: str,
) -> Set[str]:
    response = _recorded_request(
        session,
        diagnostics,
        "GET",
        collection_url,
        verify_ssl=verify_ssl,
        label=label,
    )
    payload = _response_payload(response)
    _assert_application_success(response, payload, label)
    if payload is None or not isinstance(payload.get("data"), list):
        raise AssertionError(f"{label} returned an invalid object inventory")
    return _object_ids(payload, names)


def _cleanup_objects(
    session: requests.Session,
    diagnostics: DiagnosticsCollector,
    collection_url: str,
    names: Set[str],
    known_ids: Iterable[str],
    verify_ssl: bool,
) -> None:
    cleanup_errors = []
    object_ids = set(known_ids)
    try:
        object_ids.update(
            _matching_object_ids(
                session,
                diagnostics,
                collection_url,
                names,
                verify_ssl,
                "disposable write cleanup discovery",
            )
        )
    except Exception as exc:  # noqa: BLE001 - continue deleting known objects
        cleanup_errors.append(f"discovery failed ({type(exc).__name__})")

    for object_id in sorted(object_ids):
        try:
            response = _recorded_request(
                session,
                diagnostics,
                "DELETE",
                f"{collection_url}/{quote(object_id, safe='')}",
                verify_ssl=verify_ssl,
                label="disposable write cleanup delete",
            )
            _assert_application_success(
                response,
                _response_payload(response),
                "disposable write cleanup delete",
            )
        except Exception as exc:  # noqa: BLE001 - verify all cleanup candidates
            cleanup_errors.append(
                f"delete failed for a disposable object ({type(exc).__name__})"
            )

    remaining_ids: Set[str] = set()
    try:
        remaining_ids = _matching_object_ids(
            session,
            diagnostics,
            collection_url,
            names,
            verify_ssl,
            "disposable write cleanup verification",
        )
    except Exception as exc:  # noqa: BLE001 - an unverifiable cleanup is a failure
        cleanup_errors.append(f"verification failed ({type(exc).__name__})")
    if remaining_ids:
        cleanup_errors.append("a disposable object still exists after cleanup")
    if cleanup_errors:
        diagnostics.notes.append("disposable write cleanup could not be verified")
        raise AssertionError(
            "disposable write cleanup failed: " + "; ".join(cleanup_errors)
        )


def run_disposable_write_round_trip(
    session: requests.Session,
    diagnostics: DiagnosticsCollector,
    base_url: str,
    verify_ssl: bool,
    unique_name: str,
) -> None:
    """Create, update, delete, and verify absence of an inert user group."""
    collection_url = f"{base_url}{WRITE_COLLECTION_PATH}"
    updated_name = f"{unique_name}-updated"
    names = {unique_name, updated_name}
    known_ids: Set[str] = set()
    create_payload = {
        "name": unique_name,
        "qos_rate_max_down": -1,
        "qos_rate_max_up": -1,
    }
    try:
        response = _recorded_request(
            session,
            diagnostics,
            "POST",
            collection_url,
            verify_ssl=verify_ssl,
            label="disposable write create",
            json=create_payload,
        )
        payload = _response_payload(response)
        # Capture an identifier before assertions so even an inconsistent error
        # response cannot bypass cleanup.
        known_ids.update(_object_ids(payload, {unique_name}))
        _assert_application_success(response, payload, "disposable write create")
        if not known_ids:
            known_ids.update(
                _matching_object_ids(
                    session,
                    diagnostics,
                    collection_url,
                    {unique_name},
                    verify_ssl,
                    "disposable write create verification",
                )
            )
        if len(known_ids) != 1:
            raise AssertionError("create did not produce exactly one disposable object")

        object_id = next(iter(known_ids))
        update_payload = dict(create_payload, name=updated_name)
        response = _recorded_request(
            session,
            diagnostics,
            "PUT",
            f"{collection_url}/{quote(object_id, safe='')}",
            verify_ssl=verify_ssl,
            label="disposable write update",
            json=update_payload,
        )
        payload = _response_payload(response)
        returned_ids = _object_ids(payload, {updated_name})
        if returned_ids and returned_ids != {object_id}:
            raise AssertionError("update returned an unexpected disposable object")
        _assert_application_success(response, payload, "disposable write update")
        visible_ids = _matching_object_ids(
            session,
            diagnostics,
            collection_url,
            {updated_name},
            verify_ssl,
            "disposable write update verification",
        )
        if object_id not in visible_ids:
            raise AssertionError("updated disposable object was not observed")
    finally:
        _cleanup_objects(
            session,
            diagnostics,
            collection_url,
            names,
            known_ids,
            verify_ssl,
        )
