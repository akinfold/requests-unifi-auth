import pytest
import requests
from unittest.mock import Mock, patch
from requests import PreparedRequest, Response
from requests.cookies import RequestsCookieJar

from requests_unifi_auth.auth import UnifiControllerAuth


class TestUnifiControllerAuth:

    @pytest.fixture
    def auth(self):
        return UnifiControllerAuth("test_user", "test_pass", "ctrl.example")

    @pytest.fixture
    def mock_response(self):
        response = Mock(spec=Response)
        response.status_code = 200
        response.url = "https://ctrl.example/api/test"
        response.headers = {}
        response.cookies = None
        return response

    def test_init(self):
        auth = UnifiControllerAuth("user", "pass", "ctrl.example")
        assert auth.username == "user"
        assert auth.password == "pass"
        assert auth.controller_netloc == "ctrl.example"
        assert auth._cookies is None
        assert auth._csrf_token is None

    def test_eq_and_ne(self):
        a = UnifiControllerAuth("user", "pass", "ctrl.example")
        b = UnifiControllerAuth("user", "pass", "ctrl.example")
        c = UnifiControllerAuth("other", "pass", "ctrl.example")

        assert a == b
        assert not (a != b)
        assert a != c
        assert not (a == c)

    def test_set_cookie_success(self, auth):
        response = Mock()
        cookie_jar = RequestsCookieJar()
        response.cookies = cookie_jar
        # add an initial cookie value to the jar
        cookie_jar.set("session", "abc123", domain="ctrl.example", path="/")

        result = auth.set_cookie(response)

        assert result is True
        assert auth._cookies is cookie_jar

    def test_set_cookie_failure(self, auth):
        response = Mock()
        response.cookies = None

        result = auth.set_cookie(response)

        assert result is False
        assert auth._cookies is None

    def test_update_csrf_token_success(self, auth):
        response = Mock()
        response.headers = {'x-updated-csrf-token': 'test-token'}

        result = auth.update_csrf_token(response)

        assert result is True
        assert auth._csrf_token == 'test-token'

    def test_update_csrf_token_failure(self, auth):
        response = Mock()
        response.headers = {}

        result = auth.update_csrf_token(response)

        assert result is False
        assert auth._csrf_token is None

    def test_prepare_request_sets_cookies_and_csrf_on_prepared_request(self):
        auth = UnifiControllerAuth("u", "p", "ctrl.example")
        # prepare cookies and csrf
        jar = requests.cookies.RequestsCookieJar()
        jar.set("session", "abc123", domain="ctrl.example", path="/")
        auth._cookies = jar
        auth._csrf_token = "csrf-token-xyz"

        req = requests.Request("POST", "https://ctrl.example/api/endpoint")
        preq: PreparedRequest = requests.Session().prepare_request(req)

        # ensure headers don't already contain cookie or csrf
        assert "Cookie" not in preq.headers
        assert "X-CSRF-Token" not in preq.headers

        auth.prepare_request(preq)

        assert "Cookie" in preq.headers
        assert "X-CSRF-Token" in preq.headers
        assert preq.headers["X-CSRF-Token"] == "csrf-token-xyz"

    def test_prepare_request_safe_methods_no_csrf(self, auth):
        auth._cookies = RequestsCookieJar()
        auth._cookies.set("session", "abc123", domain="ctrl.example", path="/")
        auth._csrf_token = "csrf-token"

        # Test with safe methods that shouldn't get CSRF token
        for method in ['GET', 'OPTION', 'HEAD']:
            req = requests.Request(method, "https://ctrl.example/api/endpoint")
            preq = requests.Session().prepare_request(req)

            auth.prepare_request(preq)

            # Should have cookies but no CSRF token
            assert "Cookie" in preq.headers
            assert "X-CSRF-Token" not in preq.headers

    def test_call_registers_response_hook_on_arbitrary_request_object(self):
        class DummyReq(requests.Request):
            def __init__(self):
                super().__init__()
                self.registered = []

            def register_hook(self, name, func):
                self.registered.append((name, func))

        auth = UnifiControllerAuth("u", "p", "ctrl.example")
        dr = DummyReq()
        ret = auth.__call__(dr)
        assert ret is dr
        assert any(name == "response" and func == auth.handle_401 for name, func in dr.registered)

    def test_handle_401_non_401_returns_original(self):
        auth = UnifiControllerAuth("u", "p", "ctrl.example")
        resp = Response()
        resp.status_code = 200
        resp.url = "https://ctrl.example/api/test"
        returned = auth.handle_401(resp)
        assert returned is resp

    def test_handle_401_netloc_mismatch_returns_original(self):
        auth = UnifiControllerAuth("u", "p", "ctrl.example")
        resp = Response()
        resp.status_code = 401
        resp.url = "https://other.example/api/test"
        returned = auth.handle_401(resp)
        assert returned is resp

    def test_handle_401_authorize_failure_returns_original(self):
        class FailingAuth(UnifiControllerAuth):
            def authorize(self, response, **kwargs):
                return False

        auth = FailingAuth("u", "p", "ctrl.example")
        resp = Response()
        resp.status_code = 401
        resp.url = "https://ctrl.example/api/test"
        returned = auth.handle_401(resp)
        assert returned is resp

    @patch('requests_unifi_auth.auth.Request')
    @patch('requests_unifi_auth.auth.urlparse')
    @patch('requests_unifi_auth.auth.urlunparse')
    def test_authorize_success(self, mock_urlunparse, mock_urlparse, mock_request, auth):
        # Setup URL parsing mocks
        mock_urlparse.return_value.scheme = 'https'
        mock_urlparse.return_value.netloc = 'ctrl.example'
        mock_urlunparse.return_value = 'https://ctrl.example/api/auth/login'

        # Setup response mock
        response = Mock()
        response.url = 'https://ctrl.example/test'
        response.content = b''
        response.close = Mock()

        # Setup connection mock
        auth_response = Mock()
        auth_response.status_code = 200
        auth_response.headers = {'set-cookie': 'session=123'}
        auth_response.cookies = RequestsCookieJar()

        connection_mock = Mock()
        connection_mock.send.return_value = auth_response
        response.connection = connection_mock

        # Setup request preparation mocks
        mock_prepared_request = Mock()
        mock_request_instance = Mock()
        mock_request_instance.prepare.return_value = mock_prepared_request
        mock_request.return_value = mock_request_instance

        # Mock internal methods
        auth.set_cookie = Mock(return_value=True)
        auth.update_csrf_token = Mock(return_value=True)

        result = auth.authorize(response)

        assert result is True
        mock_request.assert_called_once_with('POST', 'https://ctrl.example/api/auth/login', json={
            "username": "test_user",
            "password": "test_pass",
            "token": "",
            "rememberMe": False
        })

    @patch('requests_unifi_auth.auth.Request')
    @patch('requests_unifi_auth.auth.urlparse')
    @patch('requests_unifi_auth.auth.urlunparse')
    def test_authorize_failure_401(self, mock_urlunparse, mock_urlparse, mock_request, auth):
        # Setup URL parsing mocks
        mock_urlparse.return_value.scheme = 'https'
        mock_urlparse.return_value.netloc = 'ctrl.example'
        mock_urlunparse.return_value = 'https://ctrl.example/api/auth/login'

        # Setup response mock
        response = Mock()
        response.url = 'https://ctrl.example/test'
        response.content = b''
        response.close = Mock()

        # Setup connection mock with 401 response
        auth_response = Mock()
        auth_response.status_code = 401
        connection_mock = Mock()
        connection_mock.send.return_value = auth_response
        response.connection = connection_mock

        # Setup request preparation mocks
        mock_prepared_request = Mock()
        mock_request_instance = Mock()
        mock_request_instance.prepare.return_value = mock_prepared_request
        mock_request.return_value = mock_request_instance

        result = auth.authorize(response)

        assert result is False

    @patch('requests_unifi_auth.auth.Request')
    @patch('requests_unifi_auth.auth.urlparse')
    @patch('requests_unifi_auth.auth.urlunparse')
    def test_authorize_failure_no_set_cookie(self, mock_urlunparse, mock_urlparse, mock_request, auth):
        # Setup URL parsing mocks
        mock_urlparse.return_value.scheme = 'https'
        mock_urlparse.return_value.netloc = 'ctrl.example'
        mock_urlunparse.return_value = 'https://ctrl.example/api/auth/login'

        # Setup response mock
        response = Mock()
        response.url = 'https://ctrl.example/test'
        response.content = b''
        response.close = Mock()

        # Setup connection mock with response missing set-cookie header
        auth_response = Mock()
        auth_response.status_code = 200
        auth_response.headers = {}
        connection_mock = Mock()
        connection_mock.send.return_value = auth_response
        response.connection = connection_mock

        # Setup request preparation mocks
        mock_prepared_request = Mock()
        mock_request_instance = Mock()
        mock_request_instance.prepare.return_value = mock_prepared_request
        mock_request.return_value = mock_request_instance

        result = auth.authorize(response)

        assert result is False
