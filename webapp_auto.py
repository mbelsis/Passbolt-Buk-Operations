"""Passbolt Bulk Tool — auto-connect launcher (cross-platform).

Passbolt has NO API keys: it is end-to-end encrypted and your OpenPGP private
key IS the API credential (every login is a signed challenge; the key is also
what decrypts data). This launcher is the closest equivalent workflow: it
reads the connection settings from credentials.json, takes the passphrase
from the OS credential store via the `keyring` library — macOS Keychain,
Windows Credential Manager, or Linux Secret Service (GNOME Keyring / KWallet)
— authenticates once at startup, and serves the web UI already connected.

Setup (one time):
  1. cp credentials.json.example.json credentials.json    and edit it
  2. python3 webapp_auto.py --set-passphrase              (stores it in the OS store)

Run:  python3 webapp_auto.py

Passphrase lookup order: PASSBOLT_PASSPHRASE env var → OS credential store →
interactive prompt. It is never written to credentials.json or any file.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import webapp
from passbolt_client import PassboltClient, PassboltError

CRED_FILE = Path(__file__).parent / "credentials.json"
SERVICE = "passbolt-bulk-tool"
ACCOUNT = os.environ.get("USER") or os.environ.get("USERNAME") or "passbolt"

try:
    import keyring
except ImportError:
    keyring = None


def set_passphrase():
    if keyring is None:
        sys.exit("The 'keyring' package is not installed: pip install keyring")
    phrase = getpass.getpass("Key passphrase to store: ")
    if not phrase:
        sys.exit("Empty passphrase, nothing stored.")
    keyring.set_password(SERVICE, ACCOUNT, phrase)
    backend = keyring.get_keyring().__class__.__name__
    print(f"Stored in the OS credential store ({backend}).")


def get_passphrase() -> str:
    env = os.environ.get("PASSBOLT_PASSPHRASE")
    if env:
        print("Passphrase: from PASSBOLT_PASSPHRASE environment variable")
        return env
    if keyring is not None:
        try:
            stored = keyring.get_password(SERVICE, ACCOUNT)
            if stored:
                backend = keyring.get_keyring().__class__.__name__
                print(f"Passphrase: from OS credential store ({backend})")
                return stored
        except Exception as exc:  # e.g. headless Linux without Secret Service
            print(f"Credential store unavailable ({exc.__class__.__name__}).")
    print("No stored passphrase — run 'python webapp_auto.py --set-passphrase' once")
    print("to save it, or set the PASSBOLT_PASSPHRASE environment variable.")
    return getpass.getpass("Key passphrase: ")


def main():
    if "--set-passphrase" in sys.argv:
        set_passphrase()
        return

    if not CRED_FILE.exists():
        sys.exit(
            f"{CRED_FILE} not found.\n"
            "Copy credentials.json.example.json to credentials.json and fill it in."
        )
    cred = json.loads(CRED_FILE.read_text())

    parts = urlsplit(cred["base_url"].strip())
    if not parts.scheme or not parts.netloc:
        sys.exit(f"Invalid base_url in credentials.json: {cred['base_url']!r}")
    base_url = f"{parts.scheme}://{parts.netloc}"

    key_file = Path(cred["key_file"]).expanduser()
    if not key_file.exists():
        sys.exit(f"Key file not found: {key_file}")

    verify: bool | str = cred.get("verify", True)
    ca_file = cred.get("ca_file")
    if verify and ca_file:
        ca_path = Path(ca_file).expanduser()
        if not ca_path.exists():
            sys.exit(f"CA file not found: {ca_path}")
        verify = str(ca_path)

    config = {
        "base_url": base_url,
        "private_key": key_file.read_text(),
        "passphrase": get_passphrase(),
        "gpg_library": cred.get("gpg_library", "PGPy"),
        "fingerprint": cred.get("fingerprint", ""),
        "user_id": cred.get("user_id", ""),
        "verify": verify,
    }

    print(f"Connecting to {base_url} …")
    try:
        client = PassboltClient(dict_config=config)
    except PassboltError as exc:
        sys.exit(f"Login failed: {exc}")
    except Exception as exc:
        if "Passphrase" in str(exc):
            sys.exit("Login failed: wrong key passphrase.")
        raise
    if not client.authenticated or not client.user_id:
        sys.exit("Login failed — check credentials.json.")
    print(f"Authenticated as user id {client.user_id}")

    webapp._client = client  # the web UI starts pre-connected
    webapp.main()


if __name__ == "__main__":
    main()
