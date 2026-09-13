import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from types import SimpleNamespace

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.exceptions import RequestException, UnrewindableBodyError

from requests_unifi_auth import UnifiControllerAuth


ORIGIN = "https://ctrl.example"


class TrackingBody(io.BytesIO):
    def __init__(self, body, headers):
        super().__init__(body)
        message = Message()
        for key, value in headers:
            message.add_header(key, value)
        self._original_response = SimpleNamespace(msg=message)
        self.released = False

    def stream(self, chunk_size, decode_content=True):
        while True:
            chunk = self.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def release_conn(self):
        self.released = True


class ScriptedAdapter(BaseAdapter):
    def __init__(self, replies):
        self.replies = iter(replies)
        self.sent = []
        self.responses = []
        self.options = []

    def send(self, request, **kwargs):
        body = request.body
        if hasattr(body, "read"):
            body = body.read()
        elif body is not None and not isinstance(body, (str, bytes, bytearray)):
            body = b"".join(body)
        self.sent.append((request.url, dict(request.headers), body))
        self.options.append(kwargs)
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        status, headers, payload = reply
        response = requests.Response()
        response.status_code = status
        response.headers.update(headers)
        response.url = request.url
        response.request = request
        response.connection = self
        response.raw = TrackingBody(payload, headers)
        extract_cookies_to_jar(response.cookies, request, response.raw)
        self.responses.append(response)
        return response

    def close(self):
        pass


def reply(status=200, cookie=None, csrf=None, location=None, payload=b"ok"):
    headers = []
    if cookie:
        headers.append(("Set-Cookie", cookie))
    if csrf:
        headers.append(("x-updated-csrf-token", csrf))
    if location:
        headers.append(("Location", location))
    return status, headers, payload


def setup_session(replies, **auth_kwargs):
    auth = UnifiControllerAuth(
        "synthetic-user", "synthetic-password", "ctrl.example", **auth_kwargs
    )
    adapter = ScriptedAdapter(replies)
    session = requests.Session()
    session.trust_env = False
    session.auth = auth
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session, auth, adapter


def seed(auth, session=None):
    auth._cookies = requests.cookies.RequestsCookieJar()
    auth._cookies.set("session", "OLD", domain="ctrl.example", path="/")
    auth._csrf_token = "OLD-CSRF"
    if session is not None:
        session.cookies.update(auth._cookies)
        session.cookies.set("preference", "keep", domain="ctrl.example", path="/")


def test_reauth_replaces_stale_cookie_and_keeps_unrelated_cookie():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply(), reply()]
    )
    seed(auth, session)
    result = session.post(ORIGIN + "/resource", data=b"payload")
    session.get(ORIGIN + "/next")
    assert "session=OLD" in adapter.sent[0][1]["Cookie"]
    for index in (2, 3):
        assert "session=NEW" in adapter.sent[index][1]["Cookie"]
        assert "session=OLD" not in adapter.sent[index][1]["Cookie"]
        assert "preference=keep" in adapter.sent[index][1]["Cookie"]
    assert all(item.request.url != ORIGIN + auth.AUTH_URL for item in result.history)


@pytest.mark.parametrize("status", [200, 401, 403, 500])
def test_internal_login_response_is_released(status):
    session, auth, adapter = setup_session(
        [reply(401), reply(status, cookie="session=NEW; Path=/"), reply()]
    )
    response = session.get(ORIGIN + "/resource", stream=True)
    assert adapter.responses[0].raw.released
    assert adapter.responses[1].raw.released
    assert response.content == b"ok"
    assert len(adapter.sent) == (3 if status == 200 else 2)


def test_tokenless_login_clears_old_csrf():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply()]
    )
    seed(auth)
    session.post(ORIGIN + "/resource")
    assert auth._csrf_token is None
    assert "X-CSRF-Token" not in adapter.sent[2][1]


@pytest.mark.parametrize(
    "target",
    [
        "https://other.example/path",
        "https://sub.ctrl.example/path",
        "https://ctrl.example:8443/path",
        "http://ctrl.example/path",
    ],
)
def test_direct_foreign_origin_strips_managed_state(target):
    session, auth, adapter = setup_session([reply(401)])
    seed(auth, session)
    session.post(target, headers={"X-CSRF-Token": "OLD-CSRF"})
    assert len(adapter.sent) == 1
    assert "session=OLD" not in adapter.sent[0][1].get("Cookie", "")
    assert "X-CSRF-Token" not in adapter.sent[0][1]


@pytest.mark.parametrize(
    "target", ["https://ctrl.example:8443/other", "http://ctrl.example/other"]
)
def test_challenge_cookie_is_stripped_from_other_origins(target):
    session, auth, adapter = setup_session(
        [
            reply(401, cookie="bootstrap=PRIVATE; Path=/"),
            reply(cookie="session=NEW; Path=/"),
            reply(),
            reply(),
        ]
    )
    result = session.get(ORIGIN + "/resource")
    assert result.status_code == 200
    assert session.cookies.get("bootstrap") == "PRIVATE"
    assert "bootstrap" in auth._managed_cookie_names

    session.get(target)
    assert "bootstrap=PRIVATE" not in adapter.sent[-1][1].get("Cookie", "")


@pytest.mark.parametrize("status", [302, 303, 307, 308])
@pytest.mark.parametrize(
    "location",
    [
        "http://ctrl.example/path",
        "//other.example/path",
        "https://ctrl.example:8443/path",
    ],
)
def test_forbidden_redirect_never_reaches_adapter(status, location):
    session, auth, adapter = setup_session([reply(status, location=location), reply()])
    seed(auth, session)
    with pytest.raises(RequestException):
        session.post(ORIGIN + "/resource")
    assert len(adapter.sent) == 1
    assert adapter.responses[0].raw.released


@pytest.mark.parametrize("status", [302, 307])
def test_redirect_after_login_is_blocked_before_stale_session_cookie_returns(status):
    session, auth, adapter = setup_session(
        [
            reply(401),
            reply(cookie="session=NEW; Path=/"),
            reply(status, location="/next"),
            reply(),
        ]
    )
    seed(auth, session)
    with pytest.raises(RequestException):
        session.get(ORIGIN + "/resource")
    assert len(adapter.sent) == 3
    assert "session=NEW" in adapter.sent[2][1]["Cookie"]


@pytest.mark.parametrize("position", [0, 3])
def test_seekable_body_replays_from_original_position(position):
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply()]
    )
    body = io.BytesIO(b"PREFIX-PAYLOAD")
    body.seek(position)
    session.post(ORIGIN + "/resource", data=body)
    assert adapter.sent[0][2] == adapter.sent[2][2] == b"PREFIX-PAYLOAD"[position:]


def test_generator_body_is_not_retried():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply()]
    )
    with pytest.raises(UnrewindableBodyError):
        session.post(ORIGIN + "/resource", data=iter([b"payload"]))
    assert len(adapter.sent) == 1


def test_user_hooks_keep_order_and_original_list():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply()]
    )
    request = session.prepare_request(requests.Request("GET", ORIGIN + "/resource"))
    seen = []

    def before(response, **kwargs):
        seen.append(("before", response.status_code))

    def after(response, **kwargs):
        seen.append(("after", response.status_code))

    request.hooks["response"].insert(0, before)
    request.hooks["response"].append(after)
    original = list(request.hooks["response"])
    session.send(request)
    assert seen == [("before", 401), ("after", 200)]
    assert request.hooks["response"] == original


def test_retry_response_updates_cookie_and_csrf():
    session, auth, adapter = setup_session(
        [
            reply(401),
            reply(cookie="session=NEW; Path=/", csrf="LOGIN"),
            reply(cookie="session=ROTATED; Path=/", csrf="ROTATED"),
            reply(),
        ]
    )
    session.get(ORIGIN + "/resource")
    session.post(ORIGIN + "/next")
    assert adapter.sent[-1][1]["Cookie"] == "session=ROTATED"
    assert adapter.sent[-1][1]["X-CSRF-Token"] == "ROTATED"


def test_ordinary_response_cookie_merge_and_deletion():
    session, auth, adapter = setup_session(
        [
            reply(cookie="other=keep; Path=/"),
            reply(cookie="session=; Path=/; Max-Age=0"),
            reply(),
        ]
    )
    seed(auth, session)
    session.get(ORIGIN + "/resource")
    assert auth._cookies.get("session") == "OLD"
    assert auth._cookies.get("other") == "keep"
    session.get(ORIGIN + "/resource")
    session.get(ORIGIN + "/next")
    assert "session=" not in adapter.sent[-1][1].get("Cookie", "")
    assert "other=keep" in adapter.sent[-1][1]["Cookie"]


@pytest.mark.parametrize(
    "authority, url, expected",
    [
        ("CTRL.example", "https://ctrl.example/resource", "https://ctrl.example"),
        (
            "ctrl.example:443",
            "https://CTRL.example:443/resource",
            "https://ctrl.example",
        ),
        (
            "bücher.example",
            "https://xn--bcher-kva.example/resource",
            "https://xn--bcher-kva.example",
        ),
        (
            "xn--bcher-kva.example",
            "https://bücher.example/resource",
            "https://xn--bcher-kva.example",
        ),
        (
            "[2001:0db8:0:0:0:0:0:1]:443",
            "https://[2001:db8::1]/resource",
            "https://[2001:db8::1]",
        ),
        (
            "ctrl.example:8443",
            "https://ctrl.example:8443/resource",
            "https://ctrl.example:8443",
        ),
    ],
)
def test_canonical_controller_origin(authority, url, expected):
    auth = UnifiControllerAuth("user", "password", authority)
    assert auth.controller_origin == expected
    assert auth.is_controller_url(url)
    assert auth == UnifiControllerAuth("user", "password", expected[len("https://") :])


@pytest.mark.parametrize(
    "authority",
    [
        "",
        "https://ctrl.example",
        "user:password@ctrl.example",
        "ctrl.example/",
        "ctrl.example?query",
        "ctrl.example#fragment",
        "ctrl.example:",
        "ctrl.example:0",
        "ctrl.example:65536",
        "ctrl.example:-1",
        "ctrl.example:abc",
        "ctrl.example:443:80",
        "[2001:db8::1",
        "2001:db8::1",
        "[::1]suffix",
        "[v1.foo]",
        "[::1]:",
        "[::1]:443junk",
        "ctrl.example\\other",
        "ctrl.example\n",
        " ctrl.example",
        "ctrl.example\t",
        "ctrl%2eexample",
        "[fe80::1%25eth0]",
    ],
)
def test_constructor_rejects_invalid_authority(authority):
    with pytest.raises(ValueError):
        UnifiControllerAuth("user", "password", authority)


@pytest.mark.parametrize(
    "url",
    [
        "http://ctrl.example/",
        "https://ctrl.example:8443/",
        "https://other.example/",
        "https://user:password@ctrl.example/",
        "https://ctrl.example:/",
        "https://ctrl.example:65536/",
        "ftp://ctrl.example/",
        "//ctrl.example/",
        "https://ctrl.example\n/",
        "https://ctrl%2eexample/",
        None,
    ],
)
def test_matcher_rejects_other_or_malformed_origins(url):
    auth = UnifiControllerAuth("user", "password", "ctrl.example")
    assert not auth.is_controller_url(url)


def test_http_requires_explicit_scheme_and_opt_in():
    with pytest.raises(ValueError, match="allow_insecure_http"):
        UnifiControllerAuth("user", "password", "ctrl.example", scheme="http")
    with pytest.raises(ValueError, match="scheme"):
        UnifiControllerAuth("user", "password", "ctrl.example", scheme="ftp")
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply()],
        scheme="http",
        allow_insecure_http=True,
    )
    session.get("http://ctrl.example/resource")
    assert adapter.sent[1][0] == "http://ctrl.example/api/auth/login"
    assert not auth.is_controller_url(ORIGIN + "/resource")


def test_initial_http_401_never_sends_credentials():
    session, auth, adapter = setup_session([reply(401)])
    result = session.get("http://ctrl.example/resource")
    assert result.status_code == 401
    assert len(adapter.sent) == 1
    assert adapter.sent[0][2] is None


def test_http_opt_in_does_not_change_default_https_origin():
    auth = UnifiControllerAuth(
        "user", "password", "ctrl.example", allow_insecure_http=True
    )
    assert auth.controller_origin == ORIGIN
    assert not auth.is_controller_url("http://ctrl.example/")


def test_malformed_redirect_is_closed_before_raising():
    session, auth, adapter = setup_session([reply(302, location="https://[invalid/")])
    with pytest.raises(RequestException):
        session.get(ORIGIN + "/resource")
    assert len(adapter.sent) == 1
    assert adapter.responses[0].raw.released


def test_login_uses_canonical_origin_and_preserves_transport_options():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply()]
    )
    session.get(
        "https://CTRL.example:443/resource",
        timeout=(2, 3),
        verify="synthetic-ca.pem",
        cert=("synthetic.crt", "synthetic.key"),
        proxies={"https": "http://proxy.example:8080"},
    )
    assert adapter.sent[1][0] == ORIGIN + "/api/auth/login"
    assert json.loads(adapter.sent[1][2])["username"] == "synthetic-user"
    assert adapter.options[0] == adapter.options[1] == adapter.options[2]


@pytest.mark.parametrize(
    "cookie", [None, "session=NEW; Domain=other.example", "session=; Max-Age=0; Path=/"]
)
def test_login_without_usable_cookie_fails_and_closes_response(cookie):
    session, auth, adapter = setup_session([reply(401), reply(cookie=cookie)])
    result = session.get(ORIGIN + "/resource")
    assert result.status_code == 401
    assert len(adapter.sent) == 2
    assert adapter.responses[1].raw.released
    assert not auth._cookies


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_login_redirect_is_not_followed(status):
    session, auth, adapter = setup_session(
        [
            reply(401),
            reply(
                status, cookie="session=NEW; Path=/", location="//other.example/login"
            ),
        ]
    )
    result = session.get(ORIGIN + "/resource")
    assert result.status_code == 401
    assert len(adapter.sent) == 2
    assert adapter.responses[1].raw.released


@pytest.mark.parametrize("body", [None, b"", b"payload", "payload"])
def test_buffered_body_replays_unchanged(body):
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply()]
    )
    session.post(ORIGIN + "/resource", data=body)
    assert adapter.sent[0][2] == adapter.sent[2][2]


@pytest.mark.parametrize("broken", ["tell", "seek"])
def test_broken_stream_cannot_be_retried(broken):
    class BrokenStream(io.BytesIO):
        def tell(self):
            if broken == "tell":
                raise OSError("tell failed")
            return super().tell()

        def seek(self, *args):
            if broken == "seek":
                raise OSError("seek failed")
            return super().seek(*args)

    session, auth, adapter = setup_session([reply(401)])
    with pytest.raises(UnrewindableBodyError):
        session.post(ORIGIN + "/resource", data=BrokenStream(b"payload"))
    assert len(adapter.sent) == 1
    assert adapter.responses[0].raw.released


def test_retry_401_does_not_trigger_another_login():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/"), reply(401)]
    )
    response = session.get(ORIGIN + "/resource")
    assert response.status_code == 401
    assert len(adapter.sent) == 3


def test_streaming_final_response_remains_unconsumed():
    session, auth, adapter = setup_session(
        [
            reply(401),
            reply(cookie="session=NEW; Path=/"),
            reply(payload=b"streamed payload"),
        ]
    )
    result = session.get(ORIGIN + "/resource", stream=True)
    assert not result._content_consumed
    assert not result.raw.released
    assert adapter.responses[1].raw.released
    assert b"".join(result.iter_content(3)) == b"streamed payload"
    result.close()


def test_login_content_exception_closes_response():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/")]
    )
    original_send = adapter.send

    def send(request, **kwargs):
        response = original_send(request, **kwargs)
        if request.url.endswith(auth.AUTH_URL):

            def fail(*args, **kwargs):
                raise requests.exceptions.ChunkedEncodingError(
                    "synthetic stream failure"
                )

            response.raw.stream = fail
        return response

    adapter.send = send
    with pytest.raises(requests.exceptions.ChunkedEncodingError):
        session.get(ORIGIN + "/resource")
    assert adapter.responses[1].raw.closed
    assert adapter.responses[1].raw.released
    assert auth._cookies is None


def test_login_cookie_parse_exception_closes_response():
    session, auth, adapter = setup_session(
        [reply(401), reply(cookie="session=NEW; Path=/")]
    )
    original_send = adapter.send

    def send(request, **kwargs):
        response = original_send(request, **kwargs)
        if request.url.endswith(auth.AUTH_URL):

            def fail():
                raise ValueError("synthetic cookie parse failure")

            response.cookies.copy = fail
        return response

    adapter.send = send
    with pytest.raises(ValueError, match="cookie parse"):
        session.get(ORIGIN + "/resource")
    assert adapter.responses[1].raw.released
    assert auth._cookies is None


@pytest.mark.parametrize("status", [302, 303, 307, 308])
@pytest.mark.parametrize(
    "location",
    ["/next", "next", "https://ctrl.example:443/next", "//ctrl.example/next"],
)
def test_ordinary_same_origin_redirect_remains_supported(status, location):
    session, auth, adapter = setup_session([reply(status, location=location), reply()])
    result = session.get(ORIGIN + "/resource")
    assert result.status_code == 200
    assert len(adapter.sent) == 2
    assert "Cookie" not in adapter.sent[-1][1]
    assert "X-CSRF-Token" not in adapter.sent[-1][1]


@pytest.mark.parametrize("status", [302, 303, 307, 308])
@pytest.mark.parametrize("initial_state", [False, True])
@pytest.mark.parametrize("update", ["cookie", "csrf", "both", "deletion"])
def test_same_origin_redirect_with_auth_update_is_blocked(
    status, initial_state, update
):
    cookie = "session=NEW; Path=/" if update in {"cookie", "both"} else None
    if update == "deletion":
        cookie = "session=; Path=/; Max-Age=0"
    csrf = "NEW-CSRF" if update in {"csrf", "both"} else None
    session, auth, adapter = setup_session(
        [reply(status, cookie=cookie, csrf=csrf, location="/next"), reply()]
    )
    if initial_state:
        seed(auth, session)
    with pytest.raises(RequestException):
        session.post(ORIGIN + "/resource", data=b"payload")
    assert len(adapter.sent) == 1
    assert adapter.responses[0].raw.released


@pytest.mark.parametrize("state", ["cookie", "csrf", "session_cookie"])
def test_same_origin_redirect_with_outgoing_state_is_blocked(state):
    session, auth, adapter = setup_session([reply(307, location="/next"), reply()])
    if state == "csrf":
        auth._csrf_token = "OLD-CSRF"
    elif state == "cookie":
        seed(auth)
        auth._csrf_token = None
    else:
        session.cookies.set("session", "OLD", domain="ctrl.example", path="/")
    with pytest.raises(RequestException):
        session.post(ORIGIN + "/resource")
    assert len(adapter.sent) == 1


def test_cross_origin_redirect_is_blocked_even_without_following():
    session, auth, adapter = setup_session(
        [reply(302, location="//other.example/path")]
    )
    with pytest.raises(RequestException):
        session.get(ORIGIN + "/resource", allow_redirects=False)
    assert len(adapter.sent) == 1


def test_later_independent_redirect_cannot_restore_prelogin_session_cookie():
    session, auth, adapter = setup_session(
        [
            reply(401),
            reply(cookie="session=NEW; Path=/"),
            reply(),
            reply(302, location="/next"),
            reply(),
        ]
    )
    seed(auth, session)
    session.get(ORIGIN + "/resource")
    assert session.cookies.get("session") == "OLD"
    with pytest.raises(RequestException):
        session.get(ORIGIN + "/independent")
    assert len(adapter.sent) == 4
    assert "session=NEW" in adapter.sent[-1][1]["Cookie"]


@pytest.mark.parametrize("prepared", [True, False])
@pytest.mark.parametrize(
    "target", [ORIGIN + "/resource", "https://ctrl.example:8443/resource"]
)
def test_explicit_cookie_header_preserves_only_unrelated_values(prepared, target):
    auth = UnifiControllerAuth("user", "password", "ctrl.example")
    seed(auth)
    request = requests.Request(
        "POST",
        target,
        headers={"cookie": "session=STALE; other=keep", "x-csrf-token": "STALE"},
    )
    if prepared:
        request = request.prepare()
    auth.prepare_request(request)
    if not prepared:
        request = request.prepare()
    if target.startswith(ORIGIN + "/"):
        assert request.headers["Cookie"] == "other=keep; session=OLD"
        assert request.headers["X-CSRF-Token"] == "OLD-CSRF"
    else:
        assert request.headers["Cookie"] == "other=keep"
        assert "X-CSRF-Token" not in request.headers


@pytest.mark.parametrize("outcome", ["success", "failure", "exception"])
def test_concurrent_challenges_share_one_login_transaction(outcome):
    auth = UnifiControllerAuth("user", "password", "ctrl.example")
    barrier = threading.Barrier(2)
    adapter = ScriptedAdapter([])
    send_lock = threading.Lock()
    login_count = 0
    retries = []

    def send(request, **kwargs):
        nonlocal login_count
        if request.url.endswith(auth.AUTH_URL):
            with send_lock:
                login_count += 1
            if outcome == "exception":
                raise requests.exceptions.ConnectionError("synthetic login failure")
            response = make_response(
                request,
                reply(
                    200 if outcome == "success" else 403,
                    cookie="session=NEW; Path=/",
                    csrf="NEW-CSRF",
                ),
            )
        elif "session=NEW" in request.headers.get("Cookie", ""):
            with send_lock:
                retries.append(dict(request.headers))
            response = make_response(request, reply())
        else:
            barrier.wait(timeout=5)
            response = make_response(request, reply(401))
        return response

    def make_response(request, specification):
        status, headers, payload = specification
        response = requests.Response()
        response.status_code = status
        response.headers.update(headers)
        response.request = request
        response.url = request.url
        response.connection = adapter
        response.raw = TrackingBody(payload, headers)
        extract_cookies_to_jar(response.cookies, request, response.raw)
        return response

    adapter.send = send
    sessions = [requests.Session(), requests.Session()]
    prepared = []
    for session in sessions:
        session.trust_env = False
        session.auth = auth
        session.mount("https://", adapter)
        prepared.append(
            session.prepare_request(requests.Request("POST", ORIGIN + "/resource"))
        )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(session.send, request)
            for session, request in zip(sessions, prepared)
        ]
        if outcome == "exception":
            for future in futures:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match="synthetic login failure"
                ):
                    future.result(timeout=5)
        else:
            results = [future.result(timeout=5) for future in futures]
            assert [result.status_code for result in results] == (
                [200, 200] if outcome == "success" else [401, 401]
            )
    assert login_count == 1
    if outcome == "success":
        assert len(retries) == 2
        assert all(
            headers["Cookie"] == "session=NEW" and headers["X-CSRF-Token"] == "NEW-CSRF"
            for headers in retries
        )


def test_late_response_cannot_overwrite_new_login_generation():
    session, auth, adapter = setup_session(
        [
            reply(cookie="session=LATE; Path=/", csrf="LATE"),
            reply(401),
            reply(cookie="session=NEW; Path=/", csrf="NEW"),
            reply(),
            reply(),
        ]
    )
    old_request = session.prepare_request(requests.Request("GET", ORIGIN + "/old"))
    old_response = adapter.send(old_request)
    session.get(ORIGIN + "/resource")
    requests.hooks.dispatch_hook("response", old_request.hooks, old_response)
    session.post(ORIGIN + "/next")
    assert adapter.sent[-1][1]["Cookie"] == "session=NEW"
    assert adapter.sent[-1][1]["X-CSRF-Token"] == "NEW"


def test_late_response_cookie_name_is_contained_to_controller_origin():
    session, auth, adapter = setup_session(
        [
            reply(cookie="late_session=LATE; Path=/"),
            reply(401),
            reply(cookie="session=NEW; Path=/", csrf="NEW"),
            reply(),
            reply(),
        ]
    )
    old_request = session.prepare_request(requests.Request("GET", ORIGIN + "/old"))
    old_response = adapter.send(old_request)
    session.get(ORIGIN + "/resource")

    requests.hooks.dispatch_hook("response", old_request.hooks, old_response)
    extract_cookies_to_jar(session.cookies, old_response.request, old_response.raw)
    assert session.cookies.get("late_session") == "LATE"
    assert "late_session" in auth._managed_cookie_names

    session.get("http://ctrl.example/other")
    assert "late_session=LATE" not in adapter.sent[-1][1].get("Cookie", "")


def test_real_adapter_reuses_a_single_connection_pool_slot(monkeypatch):
    import urllib3
    from requests.adapters import HTTPAdapter

    pool = urllib3.HTTPConnectionPool("ctrl.example", maxsize=1, block=True)
    specifications = iter([reply(401), reply(cookie="session=NEW; Path=/"), reply()])
    connections = []

    def urlopen(method, url, **kwargs):
        connection = pool._get_conn(timeout=0.2)
        connections.append(connection)
        status, headers, payload = next(specifications)
        headers.append(("Content-Length", str(len(payload))))
        message = Message()
        for key, value in headers:
            message.add_header(key, value)
        response_body = io.BytesIO(payload)
        return urllib3.response.HTTPResponse(
            body=response_body,
            headers=dict(headers),
            status=status,
            preload_content=False,
            pool=pool,
            connection=connection,
            original_response=SimpleNamespace(
                msg=message,
                isclosed=lambda: response_body.closed,
                close=response_body.close,
            ),
        )

    adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1, pool_block=True)
    monkeypatch.setattr(pool, "urlopen", urlopen)
    monkeypatch.setattr(
        adapter, "get_connection_with_tls_context", lambda *args, **kwargs: pool
    )
    session = requests.Session()
    session.trust_env = False
    session.mount("https://", adapter)
    session.auth = UnifiControllerAuth("user", "password", "ctrl.example")
    result = session.get(ORIGIN + "/resource")
    assert result.status_code == 200
    assert len(connections) == 3
    assert connections[0] is connections[1] is connections[2]
    assert pool.pool.qsize() == 1
    pool.close()
