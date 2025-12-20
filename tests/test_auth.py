from unittest.mock import Mock, patch

import pytest
import requests
from requests import PreparedRequest, Request, Response
from requests.cookies import RequestsCookieJar

from requests_unifi_auth.auth import UnifiControllerAuth


class TestUnifiControllerAuth:

    @pytest.fixture
    def auth(self):
        return UnifiControllerAuth("test_user", "test_pass", "ctrl.example")

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

    def test_set_cookie_updates_existing_cookie_jar(self, auth):
        response = Mock()
        cookie_jar = RequestsCookieJar()
        cookie_jar.set("session", "old_value", domain="ctrl.example", path="/")
        response.cookies = cookie_jar

        new_cookie_jar = RequestsCookieJar()
        new_cookie_jar.set("session", "new_value", domain="ctrl.example", path="/")
        auth._cookies = new_cookie_jar

        result = auth.set_cookie(response)

        assert result is True
        assert auth._cookies is cookie_jar
        assert auth._cookies.get("session") == "old_value"

    def test_prepare_request_handles_empty_cookies(self, auth):
        req = requests.Request("POST", "https://ctrl.example/api/endpoint")
        preq = requests.Session().prepare_request(req)

        auth._cookies = None
        auth.prepare_request(preq)

        assert "Cookie" not in preq.headers

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

    def test_prepare_request_handles_no_csrf_token(self, auth):
        req = requests.Request("POST", "https://ctrl.example/api/endpoint")
        preq = requests.Session().prepare_request(req)

        auth._csrf_token = None
        auth.prepare_request(preq)

        assert "X-CSRF-Token" not in preq.headers

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

    def test_handle_401_authorize_success_retries_request(self):
        auth = UnifiControllerAuth("u", "p", "ctrl.example")
        auth.authorize = Mock(return_value=True)
        auth.prepare_request = Mock()

        # Build the original 401 response
        resp = Mock(spec=Response)
        resp.status_code = 401
        resp.url = "https://ctrl.example/api/test"

        # Original request must support copy(), returning a retry request that supports deregister_hook()
        original_req = Mock()
        retry_req = Mock()
        original_req.copy.return_value = retry_req
        retry_req.deregister_hook = Mock()
        resp.request = original_req

        # Connection should return a retry response when sending the retry request
        connection = Mock()
        retry_resp = Mock(spec=Response)
        retry_resp.history = []
        connection.send.return_value = retry_resp
        resp.connection = connection

        returned = auth.handle_401(resp)

        assert returned is retry_resp
        # original response should be appended to history
        assert returned.history[-1] is resp
        # returned.request should be set to the retry request
        assert returned.request is retry_req
        # deregister_hook must be called to avoid infinite loop
        retry_req.deregister_hook.assert_called_once_with('response', auth.handle_401)
        # prepare_request should be invoked on the retry request
        auth.prepare_request.assert_called_once_with(retry_req)

    def test_prepare_request_assigns_cookies_to_unprepared_request(self):
        auth = UnifiControllerAuth("u", "p", "ctrl.example")
        jar = RequestsCookieJar()
        jar.set("session", "abc123", domain="ctrl.example", path="/")
        auth._cookies = jar

        req = Request("POST", "https://ctrl.example/api/endpoint")
        # ensure no cookies initially
        assert getattr(req, "cookies", None) is None

        auth.prepare_request(req)

        assert getattr(req, "cookies", None) is jar
        assert req.cookies.get("session") == "abc123"

    @patch('requests_unifi_auth.auth.Request')
    @patch('requests_unifi_auth.auth.urlparse')
    @patch('requests_unifi_auth.auth.urlunparse')
    def test_authorize_failure_set_cookie_no_cookies(self, mock_urlunparse, mock_urlparse, mock_request, auth):
        # Setup URL parsing mocks
        mock_urlparse.return_value.scheme = 'https'
        mock_urlparse.return_value.netloc = 'ctrl.example'
        mock_urlunparse.return_value = 'https://ctrl.example/api/auth/login'

        # Setup response mock
        response = Mock()
        response.url = 'https://ctrl.example/test'
        response.content = b''
        response.close = Mock()

        # Setup connection mock with response that has set-cookie header but no cookies
        auth_response = Mock()
        auth_response.status_code = 200
        auth_response.headers = {'set-cookie': 'session=123'}
        auth_response.cookies = None  # cause set_cookie to return False
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
    def test_authorize_failure_update_csrf_token_returns_false(self, mock_urlunparse, mock_urlparse, mock_request, auth):
        # Setup URL parsing mocks
        mock_urlparse.return_value.scheme = 'https'
        mock_urlparse.return_value.netloc = 'ctrl.example'
        mock_urlunparse.return_value = 'https://ctrl.example/api/auth/login'

        # Setup response mock
        response = Mock()
        response.url = 'https://ctrl.example/test'
        response.content = b''
        response.close = Mock()

        # Setup connection mock with a successful auth response that includes set-cookie
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

        # Simulate set_cookie succeeding but update_csrf_token failing
        auth.set_cookie = Mock(return_value=True)
        auth.update_csrf_token = Mock(return_value=False)

        result = auth.authorize(response)

        assert result is False