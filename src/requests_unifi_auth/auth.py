from __future__ import annotations

import threading
from typing import Optional, Union
from urllib.parse import urlparse, urlunparse

from requests import PreparedRequest, Request, Response
from requests.auth import AuthBase
from requests.cookies import RequestsCookieJar


class UnifiControllerAuth(AuthBase):
    """Unifi controller specific authentication."""

    AUTH_URL = "/api/auth/login"
    AUTH_METHOD = "POST"
    _SAFE_METHODS = frozenset({"GET", "OPTIONS", "HEAD"})

    def __init__(self, username: str, password: str, controller_netloc: str) -> None:
        """
        Initializes the authentication object with the provided credentials and controller network location.

        Args:
            username (str): The username for authentication.
            password (str): The password for authentication.
            controller_netloc (str): The network location (host:port) of the controller.
        """

        self.controller_netloc = controller_netloc
        self.username = username
        self.password = password
        self._cookies: Optional[RequestsCookieJar] = None
        self._csrf_token: Optional[str] = None
        self._lock = threading.RLock()

    def set_cookie(self, response: Response) -> bool:
        if response.cookies:
            with self._lock:
                self._cookies = response.cookies
            return True
        return False

    def update_csrf_token(self, response: Response) -> bool:
        csrf_token = response.headers.get("x-updated-csrf-token")
        if csrf_token:
            with self._lock:
                self._csrf_token = csrf_token
            return True
        return False

    def authorize(self, response: Response, **kwargs) -> bool:
        resp_url_parsed = urlparse(response.url)
        url = urlunparse(
            (
                resp_url_parsed.scheme,  # scheme
                self.controller_netloc,  # netloc
                self.AUTH_URL,  # path
                "",  # params
                "",  # query
                "",  # fragment
            )
        )
        body = {
            "username": self.username,
            "password": self.password,
            "token": "",
            "rememberMe": False,
        }
        auth_request = Request(self.AUTH_METHOD, url, json=body).prepare()
        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        _ = response.content
        response.close()
        auth_resp = response.connection.send(auth_request, **kwargs)
        if auth_resp.status_code == 401 or "set-cookie" not in auth_resp.headers:
            return False

        if not self.set_cookie(auth_resp):
            return False

        # CSRF token is optional on login; some UniFi OS versions omit it
        # and may send x-updated-csrf-token on later responses instead.
        self.update_csrf_token(auth_resp)
        return True

    def handle_401(self, response: Response, **kwargs) -> Response:
        """Takes the given response and tries to authorize, if needed."""

        original_netloc = urlparse(response.url).netloc
        if original_netloc == self.controller_netloc:
            # UniFi may rotate CSRF on mutating responses after login.
            self.update_csrf_token(response)

        # If response is not 401, do not auth.
        if response.status_code != 401:
            return response

        # If request was made to a host other than controller_url do not auth.
        if original_netloc != self.controller_netloc:
            return response

        if not self.authorize(response, **kwargs):
            return response

        # Retry request after authorization.
        retry_req = response.request.copy()
        retry_req.deregister_hook("response", self.handle_401)
        self.prepare_request(retry_req)
        retry_resp = response.connection.send(retry_req, **kwargs)
        retry_resp.history.append(response)
        retry_resp.request = retry_req
        return retry_resp

    def prepare_request(self, request: Union[Request, PreparedRequest]) -> None:
        with self._lock:
            cookies = self._cookies
            csrf_token = self._csrf_token

        if cookies:
            if isinstance(request, PreparedRequest):
                request.prepare_cookies(cookies)
            else:
                request.cookies = cookies
        if csrf_token and request.method not in self._SAFE_METHODS:
            request.headers["X-CSRF-Token"] = csrf_token

    def __call__(self, request: Request) -> Request:
        self.prepare_request(request)
        request.register_hook("response", self.handle_401)
        return request

    def __eq__(self, other: object) -> bool:
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
                self.controller_netloc == getattr(other, "controller_netloc", None),
            ]
        )

    def __ne__(self, other: object) -> bool:
        return not self == other
