"""Clone structure (tab 3) against an in-memory fake Passbolt server.

Real PGP keys are generated for the test users and the shared metadata key, so
every encrypt/decrypt round trip is exercised; only HTTP is faked.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import unittest
import uuid

import httpx

from pgp_helpers import PASSPHRASE, decrypt_with, encrypt_for, new_key

import webapp  # noqa: E402  (pgp_helpers puts the project on sys.path)
from passbolt_client import PassboltClient  # noqa: E402

BASE = "https://pb.test"

KEYS = {
    "me": new_key("Me", protect=True),
    "u2": new_key("Two"),
    "u3": new_key("Three"),
}
METADATA_KEY = new_key("Metadata")
ME, U2, U3, GROUP = (str(uuid.uuid4()) for _ in range(4))
USER_KEYS = {ME: KEYS["me"], U2: KEYS["u2"], U3: KEYS["u3"]}
GROUP_MEMBERS = {GROUP: [U2, U3]}
METADATA_KEY_ID = str(uuid.uuid4())


def perm(aro: str, aro_id: str, ptype: int) -> dict:
    return {"id": str(uuid.uuid4()), "aro": aro, "aro_foreign_key": aro_id, "type": ptype}


class FakePassbolt:
    """Just enough of the Passbolt API for the clone code paths."""

    def __init__(self):
        self.requests: list[tuple[str, str]] = []
        self.fail_folder_share_for: set[str] = set()
        self.fail_resource_share = False
        self.created_resources: dict[str, dict] = {}
        self.resource_shares: dict[str, dict] = {}
        self.deleted_resources: list[str] = []

        self.src, self.sub, self.subsub = (str(uuid.uuid4()) for _ in range(3))
        self.folders = {
            self.src: {"id": self.src, "name": "PRD", "folder_parent_id": None,
                       "permissions": [perm("User", ME, 15), perm("Group", GROUP, 7)]},
            self.sub: {"id": self.sub, "name": "CustomerA", "folder_parent_id": self.src,
                       "permissions": [perm("User", ME, 15), perm("User", U2, 1)]},
            self.subsub: {"id": self.subsub, "name": "DB", "folder_parent_id": self.sub,
                          "permissions": [perm("User", ME, 15), perm("User", U3, 7)]},
        }

        self.v4_secret = json.dumps({"password": "hunter2", "description": "db root"})
        self.v5_secret = json.dumps({"object_type": "PASSBOLT_SECRET_DATA", "password": "s3cr3t"})
        self.v5_metadata = {
            "object_type": "PASSBOLT_RESOURCE_METADATA", "resource_type_id": "t-v5",
            "name": "Cloud console", "username": "admin", "uris": ["https://c.test"],
            "description": None,
        }
        self.v4_id, self.v5_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.resources = {
            self.v4_id: {
                "id": self.v4_id, "name": "DB root", "username": "root", "uri": "db.test",
                "description": None, "resource_type_id": "t-v4", "folder_parent_id": self.sub,
                "permissions": [perm("User", ME, 15), perm("User", U2, 1), perm("Group", GROUP, 7)],
            },
            self.v5_id: {
                "id": self.v5_id, "metadata": encrypt_for(METADATA_KEY, json.dumps(self.v5_metadata)),
                "metadata_key_id": METADATA_KEY_ID, "metadata_key_type": "shared_key",
                "resource_type_id": "t-v5", "folder_parent_id": self.src,
                "permissions": [perm("User", ME, 15), perm("User", U3, 7)],
            },
        }
        self.secrets = {self.v4_id: self.v4_secret, self.v5_id: self.v5_secret}

    @staticmethod
    def ok(body) -> httpx.Response:
        return httpx.Response(200, json={"header": {"code": 200, "message": "ok"}, "body": body})

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.requests.append((method, path))
        data = json.loads(request.content) if request.content else {}
        parts = path.strip("/").removesuffix(".json").split("/")

        if method == "GET" and path == "/folders.json":
            return self.ok(list(self.folders.values()))
        if method == "POST" and path == "/folders.json":
            fid = str(uuid.uuid4())
            self.folders[fid] = {"id": fid, "name": data["name"],
                                 "folder_parent_id": data["folder_parent_id"],
                                 "permissions": [perm("User", ME, 15)]}
            return self.ok(self.folders[fid])
        if method == "PUT" and parts[:2] == ["share", "folder"]:
            if parts[2] in self.fail_folder_share_for:
                return httpx.Response(400, json={"header": {"message": "boom"}, "body": None})
            self.folders[parts[2]]["permissions"] += data["permissions"]
            return self.ok(None)
        if method == "GET" and path == "/resources.json":
            return self.ok(list(self.resources.values()))
        if method == "GET" and parts[:2] == ["secrets", "resource"]:
            return self.ok({"data": encrypt_for(KEYS["me"], self.secrets[parts[2]])})
        if method == "GET" and parts[0] == "users":
            key = USER_KEYS[parts[1]]
            return self.ok({"id": parts[1], "gpgkey": {
                "id": f"gpg-{parts[1]}", "armored_key": str(key.pubkey),
                "fingerprint": key.fingerprint.replace(" ", "")}})
        if method == "GET" and path == "/metadata/keys.json":
            private = json.dumps({"object_type": "PASSBOLT_METADATA_PRIVATE_KEY",
                                  "armored_key": str(METADATA_KEY), "passphrase": ""})
            return self.ok([{
                "id": METADATA_KEY_ID, "armored_key": str(METADATA_KEY.pubkey),
                "fingerprint": METADATA_KEY.fingerprint.replace(" ", ""), "expired": None,
                "metadata_private_keys": [
                    {"user_id": None, "data": "-----BEGIN PGP MESSAGE----- (server)"},
                    {"user_id": ME, "data": encrypt_for(KEYS["me"], private)},
                ],
            }])
        if method == "POST" and path == "/resources.json":
            rid = str(uuid.uuid4())
            self.created_resources[rid] = data
            return self.ok({"id": rid})
        if method == "POST" and parts[:3] == ["share", "simulate", "resource"]:
            added: list[str] = []
            for p in data["permissions"]:
                users = [p["aro_foreign_key"]] if p["aro"] == "User" else GROUP_MEMBERS[p["aro_foreign_key"]]
                added += [u for u in users if u not in added]
            return self.ok({"changes": {"added": [{"User": {"id": u}} for u in added], "removed": []}})
        if method == "PUT" and parts[:2] == ["share", "resource"]:
            if self.fail_resource_share:
                return httpx.Response(400, json={"header": {"message": "share refused"}, "body": None})
            self.resource_shares[parts[2]] = data
            return self.ok(None)
        if method == "DELETE" and parts[0] == "resources":
            self.deleted_resources.append(parts[1])
            return self.ok(None)
        return httpx.Response(404, json={"header": {"message": f"unhandled {method} {path}"}})


def make_client(server: FakePassbolt) -> PassboltClient:
    client = PassboltClient.__new__(PassboltClient)
    client.config = {"gpg_library": "PGPy", "passphrase": PASSPHRASE}
    client.key = KEYS["me"]
    client.fingerprint = KEYS["me"].fingerprint.replace(" ", "")
    client.base_url = BASE
    client.user_id = ME
    client.authenticated = True
    client.session = httpx.Client(transport=httpx.MockTransport(server.handle))
    return client


class CloneTests(unittest.TestCase):
    def setUp(self):
        self.server = FakePassbolt()
        webapp._client = make_client(self.server)

    def clone(self, **overrides) -> list[str]:
        payload = {"source_id": self.server.src, "dest_name": "DR", "copy_root_perms": True,
                   "copy_passwords": False, "dry_run": False, **overrides}
        return webapp.api_clone(payload)["lines"]

    def folder_by_path(self, *names):
        parent = None
        for name in names:
            parent = next(f for f in self.server.folders.values()
                          if f["name"] == name and f["folder_parent_id"] == parent)["id"]
        return self.server.folders[parent]

    @staticmethod
    def grants(folder) -> set:
        return {(p["aro"], p["aro_foreign_key"], p["type"]) for p in folder["permissions"]}

    def test_structure_and_permissions_are_cloned(self):
        lines = self.clone()
        self.assertEqual(self.grants(self.folder_by_path("DR")), {("User", ME, 15), ("Group", GROUP, 7)})
        self.assertEqual(self.grants(self.folder_by_path("DR", "CustomerA")),
                         {("User", ME, 15), ("User", U2, 1)})
        self.assertEqual(self.grants(self.folder_by_path("DR", "CustomerA", "DB")),
                         {("User", ME, 15), ("User", U3, 7)})
        self.assertIn("Passwords were not touched", lines[-2])
        self.assertFalse(self.server.created_resources)

    def test_failed_permission_copy_does_not_skip_the_subtree(self):
        real_create = webapp._client.create_folder

        def create(name, parent_id=None):
            folder = real_create(name, parent_id)
            if name == "CustomerA":
                self.server.fail_folder_share_for.add(folder["id"])
            return folder

        webapp._client.create_folder = create
        lines = self.clone()
        self.assertTrue(any(l.startswith("FAIL  DR/CustomerA created, but its permissions") for l in lines))
        self.assertEqual(self.grants(self.folder_by_path("DR", "CustomerA", "DB")),
                         {("User", ME, 15), ("User", U3, 7)})

    def test_dry_run_changes_nothing_and_names_v5_passwords(self):
        lines = self.clone(copy_passwords=True, dry_run=True)
        writes = [r for r in self.server.requests if r[0] in ("POST", "PUT", "DELETE")]
        self.assertEqual(writes, [])
        self.assertFalse(any(path.startswith("/secrets/") for _, path in self.server.requests))
        self.assertIn("PLAN  copy password 'Cloud console' → DR (1 permissions)", lines)
        self.assertIn("PLAN  copy password 'DB root' → DR/CustomerA (2 permissions)", lines)
        self.assertTrue(lines[-2].startswith("DRY RUN"))

    def test_v4_password_copied_and_shared_with_re_encrypted_secrets(self):
        self.clone(copy_passwords=True)
        dest = self.folder_by_path("DR", "CustomerA")["id"]
        rid, created = next((k, v) for k, v in self.server.created_resources.items()
                            if v["folder_parent_id"] == dest)
        self.assertEqual((created["name"], created["username"], created["uri"]), ("DB root", "root", "db.test"))
        self.assertEqual(decrypt_with(KEYS["me"], created["secrets"][0]["data"]), self.server.v4_secret)

        share = self.server.resource_shares[rid]
        self.assertEqual({(p["aro"], p["aro_foreign_key"], p["type"]) for p in share["permissions"]},
                         {("User", U2, 1), ("Group", GROUP, 7)})
        by_user = {s["user_id"]: s["data"] for s in share["secrets"]}
        self.assertEqual(set(by_user), {U2, U3})  # U3 only through the group
        for uid in (U2, U3):
            self.assertEqual(decrypt_with(USER_KEYS[uid], by_user[uid]), self.server.v4_secret)

    def test_v5_password_metadata_re_encrypted_with_shared_key(self):
        self.clone(copy_passwords=True)
        dest = self.folder_by_path("DR")["id"]
        rid, created = next((k, v) for k, v in self.server.created_resources.items()
                            if v["folder_parent_id"] == dest)
        self.assertEqual(created["metadata_key_type"], "shared_key")
        self.assertEqual(created["metadata_key_id"], METADATA_KEY_ID)
        self.assertNotIn("name", created)
        self.assertEqual(json.loads(decrypt_with(METADATA_KEY, created["metadata"])), self.server.v5_metadata)
        share = self.server.resource_shares[rid]
        self.assertEqual([s["user_id"] for s in share["secrets"]], [U3])
        self.assertEqual(decrypt_with(KEYS["u3"], share["secrets"][0]["data"]), self.server.v5_secret)

    def test_failed_share_removes_the_unshared_copy(self):
        self.server.fail_resource_share = True
        lines = self.clone(copy_passwords=True)
        self.assertEqual(set(self.server.deleted_resources), set(self.server.created_resources))
        fails = [l for l in lines if l.startswith("FAIL  password")]
        self.assertEqual(len(fails), 2)
        self.assertTrue(all("removed again" in l for l in fails))


if __name__ == "__main__":
    unittest.main()
