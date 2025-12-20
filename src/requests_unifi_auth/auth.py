from urllib.parse import urlparse, urlunparse

from requests import Request, Response, PreparedRequest
from requests.auth import AuthBase


class UnifiControllerAuth(AuthBase):
    """Unifi controller specific authentication."""

    AUTH_URL = '/api/auth/login'
    AUTH_METHOD = 'POST'

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
        self._cookies = None
        self._csrf_token = None

    def set_cookie(self, response) -> bool:
        if response.cookies:
            self._cookies = response.cookies
            return True
        return False

    def update_csrf_token(self, response) -> bool:
        csrf_token = response.headers.get('x-updated-csrf-token')
        if csrf_token:
            self._csrf_token = csrf_token
            return True
        return False

    def authorize(self, response, **kwargs) -> bool:
        resp_url_parsed = urlparse(response.url)
        url = urlunparse((
            resp_url_parsed.scheme, # scheme
            self.controller_netloc, # netloc
            self.AUTH_URL,          # path
            '',                     # params
            '',                     # query
            ''                      # fragment
        ))
        body = {
            "username": self.username,
            "password": self.password,
            "token": "",
            "rememberMe": False
        }
        auth_request = Request(self.AUTH_METHOD, url, json=body).prepare()
        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        _ = response.content
        response.close()
        auth_resp = response.connection.send(auth_request, **kwargs)
        if auth_resp.status_code == 401 or 'set-cookie' not in auth_resp.headers:
            return False

        if not self.set_cookie(auth_resp):
            return False

        if not self.update_csrf_token(auth_resp):
            return False

        return True

    def handle_401(self, response: Response, **kwargs) -> Response:
        """Takes the given response and tries to authorize, if needed."""

        # If response is not 401, do not auth.
        if not response.status_code == 401:
            return response

        # If request was made to a host other than controller_url do not auth.
        original_netloc = urlparse(response.url).netloc
        if isinstance(original_netloc, (bytes, bytearray)):
            original_netloc = original_netloc.decode()
        if original_netloc != self.controller_netloc:
            return response

        if not self.authorize(response, **kwargs):
            return response
        else:
            # Retry request after authorization.
            retry_req = response.request.copy()
            retry_req.deregister_hook('response', self.handle_401)
            self.prepare_request(retry_req)
            retry_resp = response.connection.send(retry_req, **kwargs)
            retry_resp.history.append(response)
            retry_resp.request = retry_req
            return retry_resp

    def prepare_request(self, request: Request | PreparedRequest):
        if self._cookies:
            if isinstance(request, PreparedRequest):
                request.prepare_cookies(self._cookies)
            else:
                request.cookies = self._cookies
        if self._csrf_token and request.method not in {'GET', 'OPTION', 'HEAD'}:
            request.headers['X-CSRF-Token'] = self._csrf_token

    def __call__(self, request: Request):
        self.prepare_request(request)
        request.register_hook("response", self.handle_401)
        return request

    def __eq__(self, other):
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )

    def __ne__(self, other):
        return not self == other