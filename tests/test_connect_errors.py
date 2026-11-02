"""Every way Connect can fail must give a message the user can act on.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

from __future__ import annotations

import ssl
import unittest
from unittest import mock

import httpx

from pgp_helpers import PASSPHRASE, new_key

import webapp  # noqa: E402
from passbolt_client import PassboltClient, PassboltError  # noqa: E402

URL = "https://pb.test"
USER_KEY = new_key("Me", protect=True)


def connect_error(**overrides) -> str:
    payload = {"base_url": URL, "private_key": str(USER_KEY), "passphrase": PASSPHRASE}
    payload.update(overrides)
    with mock.patch.object(webapp, "_defaults", {}):
        try:
            webapp.api_connect(payload)
        except PassboltError as exc:
            return str(exc)
    raise AssertionError("connect unexpectedly succeeded")


def error_when_login_raises(exc: Exception) -> str:
    with mock.patch.object(webapp, "PassboltClient", side_effect=exc):
        return connect_error()


class InputValidationTests(unittest.TestCase):
    def test_missing_url(self):
        self.assertIn("Enter the server URL", connect_error(base_url=" "))

    def test_url_without_scheme(self):
        self.assertIn("must start with https://", connect_error(base_url="pb.test"))

    def test_url_with_unsupported_scheme(self):
        self.assertIn("must start with https://", connect_error(base_url="ftp://pb.test"))

    def test_file_that_is_not_a_key(self):
        self.assertIn("not a readable OpenPGP key", connect_error(private_key="hello"))

    def test_public_key_instead_of_private(self):
        self.assertIn("PUBLIC key", connect_error(private_key=str(USER_KEY.pubkey)))


class LoginFailureTests(unittest.TestCase):
    def test_untrusted_certificate(self):
        msg = error_when_login_raises(httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"))
        self.assertIn("not trusted", msg)
        self.assertIn("self-signed certificate", msg)

    def test_connection_refused(self):
        msg = error_when_login_raises(httpx.ConnectError("[Errno 61] Connection refused"))
        self.assertIn("refused the connection", msg)

    def test_unknown_host(self):
        msg = error_when_login_raises(httpx.ConnectError("[Errno 8] nodename nor servname provided"))
        self.assertIn("could not be found", msg)

    def test_timeout(self):
        self.assertIn("did not respond", error_when_login_raises(httpx.ConnectTimeout("timed out")))

    def test_other_network_failure(self):
        msg = error_when_login_raises(httpx.RemoteProtocolError("Server disconnected"))
        self.assertIn("Could not reach", msg)

    def test_unusable_ca_certificate(self):
        msg = error_when_login_raises(ssl.SSLError("no certificate or crl found"))
        self.assertIn("CA certificate could not be loaded", msg)

    def test_wrong_passphrase(self):
        msg = error_when_login_raises(ValueError("Passphrase was incorrect!"))
        self.assertEqual(msg, "Wrong key passphrase — try again.")

    def test_passbolt_errors_pass_through(self):
        self.assertEqual(error_when_login_raises(PassboltError("from server")), "from server")

    def test_unexpected_error_names_the_cause_without_a_traceback(self):
        with mock.patch("traceback.print_exc"):
            msg = error_when_login_raises(KeyError("challenge"))
        self.assertIn("KeyError", msg)
        self.assertNotIn("Traceback", msg)


class JwtMessageTests(unittest.TestCase):
    def jwt_error(self, user_id: str, reply: httpx.Response | None = None) -> str:
        client = PassboltClient.__new__(PassboltClient)
        client.config = {"gpg_library": "PGPy", "passphrase": PASSPHRASE, "user_id": user_id}
        client.key = USER_KEY
        client.base_url = URL
        client.session = httpx.Client(transport=httpx.MockTransport(lambda _: reply))
        server = {"keydata": str(new_key("Server").pubkey), "fingerprint": ""}
        with self.assertRaises(PassboltError) as caught:
            client._jwt_login(server)
        return str(caught.exception)

    def test_malformed_user_id_is_caught_before_the_request(self):
        self.assertIn("not a valid UUID", self.jwt_error("hello"))

    def test_rejected_login_has_a_hint_and_no_null(self):
        reply = httpx.Response(400, json={"header": {"message": "Invalid."}, "body": None})
        msg = self.jwt_error("8bb80df5-700c-48ce-b568-85a60fc3c8f2", reply)
        self.assertIn("this private key belongs", msg)
        self.assertNotIn("null", msg)


if __name__ == "__main__":
    unittest.main()
