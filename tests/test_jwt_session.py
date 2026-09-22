"""JWT sessions (Passbolt v5) renew themselves when the access token expires.

Real PGP keys drive the login challenge; only HTTP is faked.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import unittest
import uuid

import httpx

from pgp_helpers import PASSPHRASE, decrypt_with, encrypt_for, new_key

from passbolt_client import PassboltClient, PassboltError  # noqa: E402

BASE = "https://pb.test"
USER_KEY = new_key("Me", protect=True)
SERVER_KEY = new_key("Server")
USER_ID = str(uuid.uuid4())


class FakeJwtServer:
    """No GPGAuth; JWT login, single-use refresh tokens handed out as a cookie."""

    def __init__(self):
        self.valid_access: str | None = None
        self.valid_refresh: str | None = None
        self.refresh_enabled = True
        self.login_enabled = True
        self.logins = 0
        self.refreshes = 0
        self.folder_calls: list[str] = []

    @staticmethod
    def ok(body, **kwargs) -> httpx.Response:
        return httpx.Response(200, json={"header": {"code": 200}, "body": body}, **kwargs)

    @staticmethod
    def unauthorized() -> httpx.Response:
        return httpx.Response(401, json={"header": {"code": 401, "message": "expired"}, "body": None})

    def expire_access_token(self):
        self.valid_access = None

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        data = json.loads(request.content) if request.content else {}

        if path == "/auth/login.json":  # GPGAuth is not offered
            return httpx.Response(404, text="<html>not found</html>")
        if path == "/auth/verify.json":
            return self.ok({"keydata": str(SERVER_KEY.pubkey),
                            "fingerprint": SERVER_KEY.fingerprint.replace(" ", "")})
        if path == "/auth/jwt/login.json":
            if "authorization" in request.headers:
                raise AssertionError("login must be sent without a bearer token")
            if not self.login_enabled:
                return self.unauthorized()
            challenge = json.loads(decrypt_with(SERVER_KEY, data["challenge"]))
            self.logins += 1
            self.valid_access, self.valid_refresh = f"access-{uuid.uuid4()}", f"refresh-{uuid.uuid4()}"
            reply = {**challenge, "access_token": self.valid_access, "refresh_token": self.valid_refresh}
            return self.ok({"challenge": encrypt_for(USER_KEY, json.dumps(reply))})
        if path == "/auth/jwt/refresh.json":
            if "authorization" in request.headers:
                raise AssertionError("refresh must be sent without a bearer token")
            if not self.refresh_enabled or data.get("refresh_token") != self.valid_refresh:
                return httpx.Response(400, json={"header": {"message": "bad refresh token"}, "body": None})
            self.refreshes += 1
            self.valid_access, self.valid_refresh = f"access-{uuid.uuid4()}", f"refresh-{uuid.uuid4()}"
            return self.ok({"access_token": self.valid_access},
                           headers={"set-cookie": f"refresh_token={self.valid_refresh}; Path=/; HttpOnly"})
        if path == "/folders.json":
            token = request.headers.get("authorization", "").removeprefix("Bearer ")
            self.folder_calls.append(token)
            if not self.valid_access or token != self.valid_access:
                return self.unauthorized()
            return self.ok([{"id": "f1", "name": "PRD", "folder_parent_id": None}])
        return httpx.Response(404, json={"header": {"message": f"unhandled {path}"}})


def connect(server: FakeJwtServer) -> PassboltClient:
    client = PassboltClient.__new__(PassboltClient)
    client.config = {"gpg_library": "PGPy", "passphrase": PASSPHRASE, "user_id": USER_ID}
    client.key = USER_KEY
    client.fingerprint = USER_KEY.fingerprint.replace(" ", "")
    client.base_url = BASE
    client.login_url = f"{BASE}/auth/login.json"
    client.authenticated = False
    client.user_id = None
    client.session = httpx.Client(transport=httpx.MockTransport(server.handle))
    client.login()
    return client


class JwtSessionTests(unittest.TestCase):
    def setUp(self):
        self.server = FakeJwtServer()
        self.client = connect(self.server)

    def test_login_falls_back_to_jwt(self):
        self.assertTrue(self.client.authenticated)
        self.assertEqual(self.server.logins, 1)
        self.assertEqual(self.client.get_folders()[0]["name"], "PRD")

    def test_expired_token_is_refreshed_and_request_retried(self):
        self.server.expire_access_token()
        self.assertEqual(self.client.get_folders()[0]["name"], "PRD")
        self.assertEqual((self.server.refreshes, self.server.logins), (1, 1))

    def test_next_refresh_uses_the_rotated_token_from_the_cookie(self):
        for expected in (1, 2, 3):
            self.server.expire_access_token()
            self.client.get_folders()
            self.assertEqual(self.server.refreshes, expected)
        self.assertEqual(self.server.logins, 1)

    def test_rejected_refresh_falls_back_to_a_fresh_login(self):
        self.server.refresh_enabled = False
        self.server.expire_access_token()
        self.assertEqual(self.client.get_folders()[0]["name"], "PRD")
        self.assertEqual(self.server.logins, 2)

    def test_unrenewable_session_says_reconnect(self):
        self.server.refresh_enabled = False
        self.server.login_enabled = False
        self.server.expire_access_token()
        with self.assertRaisesRegex(PassboltError, "reconnect"):
            self.client.get_folders()

    def test_valid_token_is_not_refreshed(self):
        for _ in range(3):
            self.client.get_folders()
        self.assertEqual((self.server.refreshes, self.server.logins), (0, 1))


if __name__ == "__main__":
    unittest.main()
