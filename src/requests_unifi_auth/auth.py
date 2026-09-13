from __future__ import annotations

import ipaddress
import threading
from functools import partial
from typing import Optional, Union
from urllib.parse import urljoin, urlsplit

import idna
from requests import PreparedRequest, Request, Response
from requests.auth import AuthBase
from requests.cookies import (
    RequestsCookieJar,
    cookiejar_from_dict,
    extract_cookies_to_jar,
    get_cookie_header,
)
from requests.exceptions import RequestException, UnrewindableBodyError
from requests.structures import CaseInsensitiveDict
from requests.utils import rewind_body


class UnsafeRedirectError(RequestException):
    """A redirect cannot preserve the controller's authentication boundary."""


def _origin(url: str):
    if not isinstance(url, str) or any(ord(char) <= 32 for char in url):
        raise ValueError("Invalid controller URL")
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("A controller URL must use HTTP or HTTPS and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Controller URLs must not contain user information")
    if "\\" in parsed.netloc or "%" in parsed.netloc:
        raise ValueError("Invalid controller authority")
    host = parsed.hostname
    if parsed.netloc.startswith("[") and ":" not in host:
        raise ValueError("Bracketed controller hosts must be IPv6 addresses")
    if ":" in host:
        host = ipaddress.IPv6Address(host).compressed
        # urlsplit accepts trailing text after a bracketed IPv6 address.
        suffix = parsed.netloc[parsed.netloc.index("]") + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            raise ValueError("Invalid controller authority")
    else:
        host = idna.encode(host, uts46=True).decode("ascii").lower()
    if parsed.netloc.endswith(":"):
        raise ValueError("The controller port must not be empty")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise ValueError("Invalid controller port")
    return parsed.scheme, host, port


class UnifiControllerAuth(AuthBase):
    """Authenticate Requests calls to one controller origin.

    ``controller_netloc`` is an authority (host or host:port), not a URL.
    HTTPS is the default. HTTP requires both ``scheme="http"`` and
    ``allow_insecure_http=True`` and sends credentials without encryption.

    Each request can trigger one login and one retry. Seekable bodies are
    rewound; other streamed bodies raise ``UnrewindableBodyError``. Redirects
    outside the controller origin raise ``UnsafeRedirectError``. After the first
    successful automatic login, all redirects raise this error for this auth
    instance, including redirects on later requests and with
    ``allow_redirects=False``. Before login, same-origin redirects work only
    when the auth instance and outgoing request have no cookie or CSRF state
    and the response does not set, rotate, or delete that state.
    Response hooks must not change redirect targets after this auth hook runs.
    The state lock does not make a shared Requests Session thread-safe.
    """

    AUTH_URL = "/api/auth/login"
    AUTH_METHOD = "POST"
    _SAFE_METHODS = frozenset({"GET", "OPTIONS", "HEAD"})

    def __init__(
        self,
        username: str,
        password: str,
        controller_netloc: str,
        *,
        scheme: str = "https",
        allow_insecure_http: bool = False,
    ) -> None:
        if not isinstance(controller_netloc, str) or any(
            char in controller_netloc for char in "/?#@"
        ):
            raise ValueError("controller_netloc must be a host or host:port authority")
        if scheme not in {"https", "http"}:
            raise ValueError("The controller scheme must be https or http")
        if scheme == "http" and not allow_insecure_http:
            raise ValueError("HTTP requires allow_insecure_http=True")
        self._origin = _origin(f"{scheme}://{controller_netloc}")
        _, host, port = self._origin
        authority = f"[{host}]" if ":" in host else host
        if port != (443 if scheme == "https" else 80):
            authority = f"{authority}:{port}"
        self.controller_netloc = authority
        self.controller_origin = f"{scheme}://{authority}"
        self.username = username
        self.password = password
        self._cookies: Optional[RequestsCookieJar] = None
        self._csrf_token: Optional[str] = None
        self._managed_cookie_names = set()
        self._lock = threading.RLock()
        self._generation = 0
        self._login_success = False
        self._login_error = None
        self._has_logged_in = False

    def is_controller_url(self, url: str) -> bool:
        """Return whether the URL has the configured scheme, host, and port."""
        try:
            return _origin(url) == self._origin
        except (ValueError, TypeError, UnicodeError):
            return False

    @staticmethod
    def _consume_close(response: Response) -> None:
        try:
            _ = response.content
        finally:
            response.close()

    @staticmethod
    def _response_cookie_names(response: Response) -> set:
        observed = RequestsCookieJar()
        if response.request is not None:
            extract_cookies_to_jar(observed, response.request, response.raw)
        if response.cookies is not None:
            observed.update(response.cookies)
        return {cookie.name for cookie in observed}

    def _track_response_cookie_names(self, response: Response) -> None:
        if not self.is_controller_url(response.url):
            return
        names = self._response_cookie_names(response)
        if names:
            with self._lock:
                self._managed_cookie_names.update(names)

    def _merge_response(self, response: Response, generation: int) -> None:
        if not self.is_controller_url(response.url):
            return
        names = self._response_cookie_names(response)
        with self._lock:
            # Requests can import cookies from response history into its Session
            # after this hook returns. Track their names even when an old
            # generation must not update the auth state, so prepare_request can
            # keep them inside the configured origin.
            self._managed_cookie_names.update(names)
            if generation != self._generation:
                return
            jar = (
                self._cookies.copy()
                if self._cookies is not None
                else RequestsCookieJar()
            )
            self._managed_cookie_names.update(cookie.name for cookie in jar)
            # Extract into the existing jar so expiration deletes previous values
            # even when response.cookies contains no live cookie.
            if response.request is not None:
                extract_cookies_to_jar(jar, response.request, response.raw)
            if response.cookies is not None:
                jar.update(response.cookies)
            jar.clear_expired_cookies()
            self._managed_cookie_names.update(cookie.name for cookie in jar)
            self._cookies = jar
            token = response.headers.get("x-updated-csrf-token")
            if token is not None:
                self._csrf_token = token or None

    def set_cookie(self, response: Response) -> bool:
        """Merge cookies from a controller response into the current session."""
        if not self.is_controller_url(response.url):
            return False
        with self._lock:
            self._merge_response(response, self._generation)
        return bool(response.cookies)

    def update_csrf_token(self, response: Response) -> bool:
        """Accept a CSRF update only from a controller response."""
        if not self.is_controller_url(response.url):
            return False
        token = response.headers.get("x-updated-csrf-token")
        if token is not None:
            with self._lock:
                self._csrf_token = token or None
            return True
        return False

    def authorize(self, response: Response, **kwargs) -> bool:
        """Log in once for the request's generation and share its result."""
        generation = kwargs.pop("_generation", None)
        if not self.is_controller_url(response.url):
            return False
        self._consume_close(response)
        with self._lock:
            if generation is not None and generation != self._generation:
                if self._login_error is not None:
                    raise self._login_error
                return self._login_success
            auth_request = Request(
                self.AUTH_METHOD,
                self.controller_origin + self.AUTH_URL,
                json={
                    "username": self.username,
                    "password": self.password,
                    "token": "",
                    "rememberMe": False,
                },
            ).prepare()
            self._login_success = False
            self._login_error = None
            try:
                auth_response = response.connection.send(auth_request, **kwargs)
                try:
                    # Never expose the login request's password body in history.
                    _ = auth_response.content
                    jar = (
                        auth_response.cookies.copy()
                        if auth_response.cookies is not None
                        else RequestsCookieJar()
                    )
                    jar.clear_expired_cookies()
                    valid = (
                        auth_response.status_code == 200
                        and self.is_controller_url(auth_response.url)
                        and bool(get_cookie_header(jar, auth_request))
                    )
                    token = auth_response.headers.get("x-updated-csrf-token") or None
                finally:
                    auth_response.close()
                if valid:
                    if self._cookies is not None:
                        self._managed_cookie_names.update(
                            cookie.name for cookie in self._cookies
                        )
                    self._managed_cookie_names.update(cookie.name for cookie in jar)
                    self._cookies, self._csrf_token = jar, token
                    self._login_success = True
                    self._has_logged_in = True
                return self._login_success
            except Exception as error:
                self._login_error = error
                raise
            finally:
                # Failed attempts advance too, so waiters share the failure.
                self._generation += 1

    def _check_redirect(self, response: Response, after_retry: bool = False) -> None:
        if not response.is_redirect:
            return
        with self._lock:
            has_auth_state = (
                after_retry
                or self._has_logged_in
                or bool(self._cookies)
                or self._csrf_token is not None
            )
        request_headers = (
            response.request.headers if response.request is not None else {}
        )
        has_auth_state = (
            has_auth_state
            or "Cookie" in request_headers
            or "X-CSRF-Token" in request_headers
            or "Set-Cookie" in response.headers
            or "x-updated-csrf-token" in response.headers
            or bool(response.cookies)
        )
        try:
            target = urljoin(response.url, response.headers["Location"])
        except ValueError:
            target = ""
        if has_auth_state or not self.is_controller_url(target):
            self._consume_close(response)
            message = (
                "Redirects with controller authentication state are not supported"
                if has_auth_state
                else "Redirect leaves the configured controller origin"
            )
            raise UnsafeRedirectError(
                message, response=response, request=response.request
            )

    @staticmethod
    def _rewind(request: PreparedRequest) -> None:
        if request.body is None or isinstance(request.body, (bytes, str, bytearray)):
            return
        try:
            rewind_body(request)
        except (OSError, ValueError, TypeError) as error:
            raise UnrewindableBodyError(
                "The request body cannot be replayed"
            ) from error

    def handle_401(self, response: Response, **kwargs) -> Response:
        """Refresh controller state and retry one replayable unauthorized request."""
        context = kwargs.pop("_auth_context", None)
        if context is None:
            with self._lock:
                context = {"generation": self._generation, "retried": False}
        if not self.is_controller_url(response.url):
            # Session bypasses AuthBase on redirects, including a hop from an
            # unrelated URL into the controller.
            if response.is_redirect:
                self._check_redirect(response, after_retry=True)
            return response
        self._check_redirect(response)
        if response.status_code != 401:
            self._merge_response(response, context["generation"])
            return response
        # The original challenge is later exposed through response.history, and
        # Requests imports its cookies into the Session jar. Register those names
        # before returning it so port and scheme changes cannot reuse them.
        self._track_response_cookie_names(response)
        if context["retried"]:
            return response
        retry_request = response.request.copy()
        try:
            self._rewind(retry_request)
        except Exception:
            self._consume_close(response)
            raise
        context["retried"] = True
        if not self.authorize(response, _generation=context["generation"], **kwargs):
            return response
        # Adapter.send does not dispatch hooks. Keep the shared list intact so
        # Session continues with the next user hook exactly once.
        self.prepare_request(retry_request)
        generation = retry_request._unifi_generation
        retry_response = response.connection.send(retry_request, **kwargs)
        retry_response.request = retry_request
        try:
            self._check_redirect(retry_response, after_retry=True)
            self._merge_response(retry_response, generation)
        except Exception:
            retry_response.close()
            raise
        retry_response.history.append(response)
        return retry_response

    def prepare_request(self, request: Union[Request, PreparedRequest]) -> None:
        """Apply an atomic cookie and CSRF snapshot to the controller origin."""
        with self._lock:
            jar = (
                self._cookies.copy()
                if self._cookies is not None
                else RequestsCookieJar()
            )
            self._managed_cookie_names.update(cookie.name for cookie in jar)
            names = self._managed_cookie_names.copy()
            token = self._csrf_token
            request._unifi_generation = self._generation
        same_origin = self.is_controller_url(request.url)
        if not isinstance(request, PreparedRequest):
            request.headers = CaseInsensitiveDict(request.headers)
        request.headers.pop("X-CSRF-Token", None)
        if same_origin and token and request.method.upper() not in self._SAFE_METHODS:
            request.headers["X-CSRF-Token"] = token
        source = (
            request._cookies
            if isinstance(request, PreparedRequest)
            else request.cookies
        )
        cookies = source.copy() if source is not None else RequestsCookieJar()
        if isinstance(cookies, dict):
            cookies = cookiejar_from_dict(cookies)
        for cookie in list(cookies):
            if cookie.name in names:
                cookies.clear(cookie.domain, cookie.path, cookie.name)
        if same_origin:
            cookies.update(jar)
        old_header = request.headers.pop("Cookie", None)
        if isinstance(request, PreparedRequest):
            request.prepare_cookies(cookies)
        else:
            request.cookies = cookies
        if old_header is not None:
            # Explicit Cookie headers may be absent from request._cookies.
            remaining = [
                part.strip()
                for part in old_header.split(";")
                if part.strip() and part.split("=", 1)[0].strip() not in names
            ]
            request.headers.pop("Cookie", None)
            managed = get_cookie_header(jar, request) if same_origin else None
            if managed:
                remaining.append(managed)
            if remaining:
                request.headers["Cookie"] = "; ".join(remaining)

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        self.prepare_request(request)
        # Copies preserve hooks but drop custom attributes; keep the generation
        # in the hook so it survives ordinary same-origin redirects.
        context = {"generation": request._unifi_generation, "retried": False}
        request.register_hook(
            "response", partial(self.handle_401, _auth_context=context)
        )
        return request

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, UnifiControllerAuth)
            and self.username == other.username
            and self.password == other.password
            and self._origin == other._origin
        )

    def __ne__(self, other: object) -> bool:
        return not self == other
