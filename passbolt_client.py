"""Thin extension of py-passbolt with folder and folder-sharing operations.

py-passbolt (https://github.com/passbolt/lab-passbolt-py) handles the GPG
authentication handshake and gives us an authenticated httpx session; this
module adds the /folders.json and /share/folder endpoints that the library
does not cover, plus a few bulk helpers used by the GUI.

Permission types (Passbolt API):
    1  = can read
    7  = can update (read/write)
    15 = owner
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Optional
from urllib.parse import unquote

import httpx
from passbolt import PassboltAPI
from pgpy import PGPKey, PGPMessage

PERMISSION_READ = 1
PERMISSION_UPDATE = 7
PERMISSION_OWNER = 15

PERMISSION_LABELS = {
    PERMISSION_READ: "can read",
    PERMISSION_UPDATE: "can update",
    PERMISSION_OWNER: "owner",
}


class PassboltError(RuntimeError):
    """Raised when the Passbolt API returns an error response."""


def _check(response, action: str):
    """Raise PassboltError with the server message on a non-2xx response."""
    if response.status_code // 100 == 2:
        return json.loads(response.text)
    try:
        payload = json.loads(response.text)
        message = payload.get("header", {}).get("message", response.text)
        details = payload.get("body")
        if details:
            message = f"{message} — {json.dumps(details)}"
    except (ValueError, AttributeError):
        message = response.text[:500]
    raise PassboltError(f"{action} failed (HTTP {response.status_code}): {message}")


class _JwtAuth(httpx.Auth):
    """Bearer auth that survives token expiry.

    Passbolt JWT access tokens are short-lived. On a 401 the token is renewed
    (or, failing that, a fresh login is done with the key) and the request is
    sent once more. A second 401 is returned to the caller as-is.
    """

    def __init__(self, client: "PassboltClient"):
        self._client = client
        self._lock = threading.Lock()

    def sync_auth_flow(self, request):
        sent_with = self._client._jwt_access_token
        request.headers["Authorization"] = f"Bearer {sent_with}"
        response = yield request
        if response.status_code != 401:
            return
        with self._lock:
            self._client._renew_jwt(sent_with)
        request.headers["Authorization"] = f"Bearer {self._client._jwt_access_token}"
        yield request


def _cookie(jar: httpx.Cookies, name: str) -> Optional[str]:
    """Latest cookie value by name; tolerates the same name on several paths."""
    values = [c.value for c in jar.jar if c.name == name]
    return values[-1] if values else None


def _as_text(value) -> str:
    """PGPy returns str or bytearray, python-gnupg a Crypt object."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode()
    return str(value)


class PassboltClient(PassboltAPI):
    """PassboltAPI + folder CRUD and folder permission (share) management.

    Overrides login() to support both authentication schemes:
    - legacy GPGAuth (Passbolt <= v4, what py-passbolt implements), and
    - JWT auth (required on Passbolt v5+, where GPGAuth was removed).
    JWT needs the user's UUID in config["user_id"].
    """

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #

    def login(self):
        server = self._get_server_verify()
        if self._try_gpgauth():
            return
        self._jwt_login(server)

    def _get_server_verify(self) -> dict:
        """Validate the base URL and fetch the server's public OpenPGP key."""
        response = self.session.get(f"{self.base_url}/auth/verify.json", auth=None)
        try:
            body = json.loads(response.text)["body"]
        except (ValueError, KeyError):
            raise PassboltError(
                f"{self.base_url}/auth/verify.json did not return Passbolt JSON "
                f"(HTTP {response.status_code}) — check that the URL is the Passbolt "
                "base URL, without any extra path."
            )
        if not body.get("keydata"):
            raise PassboltError("Server verify response has no keydata.")
        return body

    def _try_gpgauth(self) -> bool:
        """Attempt legacy GPGAuth; return False if the server doesn't offer it."""
        post = {"data": {"gpg_auth": {"keyid": self.fingerprint}}}
        response = self.session.post(self.login_url, json=post)
        token_header = response.headers.get("x-gpgauth-user-auth-token")
        try:
            json.loads(response.text)
        except ValueError:
            return False  # HTML error page → GPGAuth removed (v5+)
        if not token_header:
            return False  # JSON error → GPGAuth disabled or key unknown
        pgp_message = unquote(token_header).replace("\\+", " ")
        nonce = self.decrypt(pgp_message)
        if isinstance(nonce, (bytes, bytearray)):
            nonce = nonce.decode()
        self.authenticated = self.stage2(str(nonce))
        if not self.authenticated:
            return False
        self.get_cookie()
        return True

    def get_cookie(self):
        """Replace py-passbolt's get_cookie: it regex-parses the Set-Cookie
        header of /users/me.json and crashes when the server doesn't send one
        there. Read the CSRF token from the cookie jar instead."""
        response = self.session.get(self.me_url)
        data = _check(response, "Read current user (/users/me.json)")
        self.user_id = data["body"]["id"]
        token = self.session.cookies.get("csrfToken")
        if not token:
            # The csrfToken cookie is set on regular page loads.
            self.session.get(self.base_url + "/")
            token = self.session.cookies.get("csrfToken")
        if token:
            self.token = token
            self.session.headers.update({"X-CSRF-Token": token})

    def _jwt_login(self, server: dict):
        user_id = (self.config.get("user_id") or "").strip()
        if not user_id:
            raise PassboltError(
                "This server uses JWT authentication (GPGAuth is not available), "
                "which requires your Passbolt User ID (a UUID). Find it in the "
                "Passbolt web app: Users → click your own name → the browser URL "
                "ends in /app/users/view/<your-user-id>. Enter it and reconnect."
            )
        challenge = {
            "version": "1.0.0",
            "domain": self.base_url,
            "verify_token": str(uuid.uuid4()),
            "verify_token_expiry": int(time.time()) + 300,
        }
        armored = self.encrypt(
            challenge,
            {"armored_key": server["keydata"], "fingerprint": server.get("fingerprint", "")},
        )
        response = self.session.post(
            f"{self.base_url}/auth/jwt/login.json",
            json={"user_id": user_id, "challenge": str(armored)},
            auth=None,
        )
        try:
            decoded = json.loads(response.text)
        except ValueError:
            raise PassboltError(
                f"JWT login failed (HTTP {response.status_code}): non-JSON response "
                f"{response.text[:200]!r}"
            )
        if response.status_code != 200:
            message = decoded.get("header", {}).get("message", "")
            raise PassboltError(
                f"JWT login failed (HTTP {response.status_code}): {message} "
                f"{json.dumps(decoded.get('body'))[:300]}"
            )
        encrypted_reply = decoded["body"]["challenge"]
        reply = self.decrypt(encrypted_reply)
        if isinstance(reply, (bytes, bytearray)):
            reply = reply.decode()
        tokens = json.loads(str(reply))
        if tokens.get("verify_token") != challenge["verify_token"]:
            raise PassboltError("JWT login: server returned a mismatched verify token.")
        self._jwt_access_token = tokens["access_token"]
        self._jwt_refresh_token = tokens.get("refresh_token")
        if not isinstance(self.session.auth, _JwtAuth):
            self.session.auth = _JwtAuth(self)
        self.user_id = user_id
        self.authenticated = True

    def _renew_jwt(self, expired_token: str):
        """Called on a 401: refresh the access token, else log in again.

        Refresh tokens are single-use; the server returns the next one as a
        cookie. Raises PassboltError when neither works (reconnect needed).
        """
        if self._jwt_access_token != expired_token:
            return  # another request already renewed it
        if self._jwt_refresh_token:
            response = self.session.post(
                f"{self.base_url}/auth/jwt/refresh.json",
                json={"user_id": self.user_id, "refresh_token": self._jwt_refresh_token},
                auth=None,
            )
            try:
                body = json.loads(response.text).get("body") or {}
            except ValueError:
                body = {}
            if response.status_code == 200 and body.get("access_token"):
                self._jwt_access_token = body["access_token"]
                self._jwt_refresh_token = body.get("refresh_token") or _cookie(
                    self.session.cookies, "refresh_token"
                )
                return
        try:
            self._jwt_login(self._get_server_verify())
        except Exception as exc:
            raise PassboltError(
                f"Your Passbolt session expired and could not be renewed ({exc}) — "
                "reconnect."
            ) from exc

    # ------------------------------------------------------------------ #
    # Folders
    # ------------------------------------------------------------------ #

    def get_folders(self, with_permissions: bool = False) -> list[dict]:
        """Return every folder visible to the authenticated user."""
        params = {"contain[permissions]": "1"} if with_permissions else {}
        response = self.session.get(f"{self.base_url}/folders.json", params=params)
        return _check(response, "List folders")["body"]

    def get_folder(self, folder_id: str, with_permissions: bool = True) -> dict:
        params = {"contain[permissions]": "1"} if with_permissions else {}
        response = self.session.get(
            f"{self.base_url}/folders/{folder_id}.json", params=params
        )
        return _check(response, f"Read folder {folder_id}")["body"]

    def create_folder(self, name: str, parent_id: Optional[str] = None) -> dict:
        payload = {"name": name, "folder_parent_id": parent_id}
        response = self.session.post(f"{self.base_url}/folders.json", json=payload)
        return _check(response, f"Create folder '{name}'")["body"]

    def rename_folder(self, folder_id: str, new_name: str) -> dict:
        response = self.session.put(
            f"{self.base_url}/folders/{folder_id}.json", json={"name": new_name}
        )
        return _check(response, f"Rename folder to '{new_name}'")["body"]

    def move_folder(self, folder_id: str, new_parent_id: Optional[str]) -> dict:
        response = self.session.put(
            f"{self.base_url}/move/folder/{folder_id}.json",
            json={"folder_parent_id": new_parent_id},
        )
        return _check(response, f"Move folder {folder_id}")

    def delete_folder(self, folder_id: str) -> dict:
        response = self.session.delete(f"{self.base_url}/folders/{folder_id}.json")
        return _check(response, f"Delete folder {folder_id}")

    def get_resources_list(self) -> list[dict]:
        """All password resources visible to the user (metadata only, no secrets)."""
        response = self.session.get(f"{self.base_url}/resources.json")
        return _check(response, "List resources")["body"]

    def get_groups_list(self) -> list[dict]:
        response = self.session.get(f"{self.base_url}/groups.json")
        return _check(response, "List groups")["body"]

    # ------------------------------------------------------------------ #
    # Sharing / permissions
    # ------------------------------------------------------------------ #

    def share_folder(self, folder_id: str, permissions: list[dict]) -> dict:
        """Apply a list of permission changes to a folder.

        Each entry is either a new permission:
            {"is_new": True, "aro": "User"|"Group", "aro_foreign_key": <uuid>,
             "aco": "Folder", "aco_foreign_key": <folder_id>, "type": 1|7|15}
        or an update to an existing one (same shape plus "id", no "is_new"),
        or a deletion (existing shape plus "delete": True).
        """
        response = self.session.put(
            f"{self.base_url}/share/folder/{folder_id}.json",
            json={"permissions": permissions},
        )
        return _check(response, f"Share folder {folder_id}")

    def set_aro_permission(
        self, folder_id: str, aro: str, aro_id: str, ptype: int
    ) -> str:
        """Grant/upgrade a User's or Group's permission on a folder.

        aro is "User" or "Group". Returns "created", "updated" or "unchanged".
        """
        folder = self.get_folder(folder_id, with_permissions=True)
        existing = None
        for perm in folder.get("permissions") or []:
            if perm.get("aro") == aro and perm.get("aro_foreign_key") == aro_id:
                existing = perm
                break

        change = {
            "aro": aro,
            "aro_foreign_key": aro_id,
            "aco": "Folder",
            "aco_foreign_key": folder_id,
            "type": ptype,
        }
        if existing is not None:
            if existing.get("type") == ptype:
                return "unchanged"
            change["id"] = existing["id"]
            self.share_folder(folder_id, [change])
            return "updated"

        change["is_new"] = True
        self.share_folder(folder_id, [change])
        return "created"

    def set_user_permission(self, folder_id: str, user_id: str, ptype: int) -> str:
        return self.set_aro_permission(folder_id, "User", user_id, ptype)

    def copy_parent_permissions(self, parent_folder: dict, new_folder_id: str) -> int:
        """Replicate a parent folder's permissions onto a newly created child.

        Passbolt's server does NOT cascade permissions to folders created via
        the API (the browser extension does that client-side), so a freshly
        created subfolder is only visible to its creator until this runs.
        Returns the number of permissions copied.
        """
        new_perms = []
        for perm in parent_folder.get("permissions") or []:
            # The creator is already sole owner of the new folder; skip self.
            if perm.get("aro") == "User" and perm.get("aro_foreign_key") == self.user_id:
                continue
            new_perms.append(
                {
                    "is_new": True,
                    "aro": perm["aro"],
                    "aro_foreign_key": perm["aro_foreign_key"],
                    "aco": "Folder",
                    "aco_foreign_key": new_folder_id,
                    "type": perm["type"],
                }
            )
        if new_perms:
            self.share_folder(new_folder_id, new_perms)
        return len(new_perms)

    # ------------------------------------------------------------------ #
    # Resources (passwords) — used only by the opt-in "copy passwords" clone
    # ------------------------------------------------------------------ #

    def get_resources_with_permissions(self) -> list[dict]:
        """All resources visible to the user, each with its permission list."""
        response = self.session.get(
            f"{self.base_url}/resources.json", params={"contain[permissions]": "1"}
        )
        return _check(response, "List resources")["body"]

    def get_resource_permissions(self, resource_id: str) -> list[dict]:
        response = self.session.get(f"{self.base_url}/permissions/resource/{resource_id}.json")
        return _check(response, f"Read permissions of resource {resource_id}")["body"]

    def decrypt_secret(self, resource_id: str) -> str:
        response = self.session.get(f"{self.base_url}/secrets/resource/{resource_id}.json")
        data = _check(response, f"Read secret of resource {resource_id}")["body"]["data"]
        return _as_text(self.decrypt(data))

    def gpgkey_of(self, user_id: str) -> dict:
        """A user's public key record (armored_key, fingerprint, id), cached."""
        cache = self.__dict__.setdefault("_gpgkey_cache", {})
        if user_id not in cache:
            response = self.session.get(f"{self.base_url}/users/{user_id}.json")
            cache[user_id] = _check(response, f"Read public key of user {user_id}")["body"]["gpgkey"]
        return cache[user_id]

    def _metadata_keys(self) -> dict[str, dict]:
        """Shared metadata keys (Passbolt v5 encrypted metadata), loaded once.

        id → {"id", "armored_key", "fingerprint", "expired",
              "private": (PGPKey, passphrase) or None}
        "private" is None when the key was never shared with this account.
        """
        cached = self.__dict__.get("_metadata_key_cache")
        if cached is not None:
            return cached
        response = self.session.get(
            f"{self.base_url}/metadata/keys.json",
            params={"contain[metadata_private_keys]": "1", "filter[deleted]": "0"},
        )
        keys = [] if response.status_code == 404 else _check(response, "List metadata keys")["body"]
        cache: dict[str, dict] = {}
        for key in keys:
            private = None
            for entry in key.get("metadata_private_keys") or []:
                # Entries with user_id null are encrypted for the server, not for us.
                if entry.get("user_id") == self.user_id and entry.get("data"):
                    decoded = json.loads(_as_text(self.decrypt(entry["data"])))
                    pgp_key, _ = PGPKey.from_blob(decoded["armored_key"])
                    private = (pgp_key, decoded.get("passphrase") or "")
            cache[key["id"]] = {
                "id": key["id"],
                "armored_key": key["armored_key"],
                "fingerprint": key.get("fingerprint", ""),
                "expired": key.get("expired"),
                "private": private,
            }
        self._metadata_key_cache = cache
        return cache

    @staticmethod
    def _decrypt_with(private: tuple, message: str) -> str:
        pgp_key, passphrase = private
        pgp_message = PGPMessage.from_blob(message)
        if pgp_key.is_protected:
            with pgp_key.unlock(passphrase):
                return _as_text(pgp_key.decrypt(pgp_message).message)
        return _as_text(pgp_key.decrypt(pgp_message).message)

    def read_resource_metadata(self, resource: dict) -> dict:
        """Cleartext metadata: v4 fields as they are, v5 metadata decrypted."""
        if not resource.get("metadata"):
            return {f: resource.get(f) for f in ("name", "username", "uri", "description")}
        if resource.get("metadata_key_type") == "user_key":
            return json.loads(_as_text(self.decrypt(resource["metadata"])))
        key = self._metadata_keys().get(resource.get("metadata_key_id"))
        if key is None or key["private"] is None:
            raise PassboltError(
                "the shared metadata key of this password is not available to your "
                "account — an administrator must share it with you in Passbolt first"
            )
        return json.loads(self._decrypt_with(key["private"], resource["metadata"]))

    def _metadata_key_for_new_resource(self, preferred_id: Optional[str]) -> Optional[dict]:
        active = [k for k in self._metadata_keys().values() if not k.get("expired")]
        for key in active:
            if key["id"] == preferred_id:
                return key
        return active[0] if active else None

    def clone_resource(
        self, resource: dict, dest_folder_id: str, permissions: list[dict]
    ) -> tuple[str, int]:
        """Create an independent copy of a password inside dest_folder_id and
        share it with the same users and groups at the same levels.

        The secret is decrypted locally, re-encrypted for the creator on
        creation, then for every user the share adds (group members expanded
        by the server's share simulation). If sharing fails, the unshared copy
        is deleted again, so a failure never leaves a stray duplicate.
        Returns (new resource id, number of permissions granted).
        """
        secret = self.decrypt_secret(resource["id"])
        me = self.gpgkey_of(self.user_id)
        others = [
            p for p in permissions
            if not (p.get("aro") == "User" and p.get("aro_foreign_key") == self.user_id)
        ]

        payload = {
            "resource_type_id": resource["resource_type_id"],
            "folder_parent_id": dest_folder_id,
            "secrets": [{"data": self.encrypt(secret, me)}],
        }
        if resource.get("expired"):
            payload["expired"] = resource["expired"]
        if resource.get("metadata"):
            metadata = json.dumps(self.read_resource_metadata(resource))
            key = self._metadata_key_for_new_resource(resource.get("metadata_key_id"))
            if key is not None:
                payload.update(
                    metadata=self.encrypt(metadata, key),
                    metadata_key_id=key["id"],
                    metadata_key_type="shared_key",
                )
            elif not others:
                payload.update(
                    metadata=self.encrypt(metadata, me),
                    metadata_key_id=me["id"],
                    metadata_key_type="user_key",
                )
            else:
                raise PassboltError("no active shared metadata key to encrypt the copy for sharing")
        else:
            for field in ("name", "username", "uri", "description"):
                payload[field] = resource.get(field)

        response = self.session.post(f"{self.base_url}/resources.json", json=payload)
        new_id = _check(response, "Create password copy")["body"]["id"]
        if not others:
            return new_id, 0

        changes = [
            {
                "is_new": True,
                "aro": p["aro"],
                "aro_foreign_key": p["aro_foreign_key"],
                "aco": "Resource",
                "aco_foreign_key": new_id,
                "type": p["type"],
            }
            for p in others
        ]
        try:
            response = self.session.post(
                f"{self.base_url}/share/simulate/resource/{new_id}.json",
                json={"permissions": changes},
            )
            simulated = _check(response, "Simulate sharing of the copy")["body"]
            added = [
                entry["User"]["id"]
                for entry in (simulated.get("changes") or {}).get("added") or []
            ]
            secrets = [
                {"user_id": uid, "data": self.encrypt(secret, self.gpgkey_of(uid))}
                for uid in added
                if uid != self.user_id
            ]
            response = self.session.put(
                f"{self.base_url}/share/resource/{new_id}.json",
                json={"permissions": changes, "secrets": secrets},
            )
            _check(response, "Share the copy")
        except Exception as exc:
            try:
                self.session.delete(f"{self.base_url}/resources/{new_id}.json")
            except Exception:
                pass
            raise PassboltError(f"{exc} — the unshared copy was removed again") from exc
        return new_id, len(changes)

    # ------------------------------------------------------------------ #
    # Convenience
    # ------------------------------------------------------------------ #

    def get_active_users(self) -> list[dict]:
        """Active, non-deleted users sorted by username (email)."""
        users = [u for u in self.get_users() if u.get("active") and not u.get("deleted")]
        return sorted(users, key=lambda u: u.get("username", ""))
