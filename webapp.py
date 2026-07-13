"""Passbolt Bulk Tool — local web UI (replaces the Tkinter GUI, which cannot
run on macOS system Tk 8.5).

Run:  python3 webapp.py        then open  http://127.0.0.1:8765

Everything runs locally: the page is served on 127.0.0.1 only, your private
key and passphrase are sent only to this local process, held in memory, and
used to authenticate against your Passbolt server.
"""

from __future__ import annotations

import json
import threading
import traceback
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from passbolt_client import (
    PERMISSION_LABELS,
    PassboltClient,
    PassboltError,
)

HOST, PORT = "127.0.0.1", 8765
CRED_FILE = Path(__file__).parent / "credentials.json"

_state_lock = threading.Lock()
_client: PassboltClient | None = None


def _load_defaults() -> tuple[dict, str]:
    """Optional credentials.json: pre-fills the form so the user only types
    the passphrase. Same file webapp_auto.py uses."""
    if CRED_FILE.exists():
        try:
            raw = CRED_FILE.read_text()
            return json.loads(raw), ""
        except ValueError as exc:
            error = f"credentials.json is invalid JSON and was IGNORED: {exc}"
            if "\\" in raw:
                error += (
                    " — hint: JSON paths must not use shell escaping; write "
                    '"/Users/x/Mobile Documents/…" with plain spaces, no backslashes.'
                )
            print(error)
            return {}, error
    return {}, ""


_defaults, _defaults_error = _load_defaults()


# --------------------------------------------------------------------------- #
# API operations
# --------------------------------------------------------------------------- #

def api_connect(payload: dict) -> dict:
    global _client
    verify: bool | str = bool(payload.get("verify", True))
    ca_cert = (payload.get("ca_cert") or "").strip()
    if verify and ca_cert:
        # Custom CA (corporate CA / TLS-inspection proxy): httpx accepts a
        # CA bundle path as its verify value.
        ca_path = Path(__file__).parent / "custom-ca.pem"
        ca_path.write_text(ca_cert + "\n")
        verify = str(ca_path)
    elif verify and _defaults.get("ca_file"):
        ca_path = Path(_defaults["ca_file"]).expanduser()
        if not ca_path.exists():
            raise PassboltError(f"ca_file from credentials.json not found: {ca_path}")
        verify = str(ca_path)

    private_key = payload.get("private_key", "")
    if not private_key and _defaults.get("key_file"):
        key_path = Path(_defaults["key_file"]).expanduser()
        if not key_path.exists():
            raise PassboltError(f"key_file from credentials.json not found: {key_path}")
        private_key = key_path.read_text()

    # Normalize to scheme://host[:port] — people paste full web-app URLs
    # like https://host/app/passwords, but the API lives at the origin.
    parts = urlsplit((payload.get("base_url") or _defaults.get("base_url", "")).strip())
    if not parts.scheme or not parts.netloc:
        raise PassboltError(f"Invalid server URL: {payload['base_url']!r}")
    base_url = f"{parts.scheme}://{parts.netloc}"
    config = {
        "base_url": base_url,
        "private_key": private_key,
        "passphrase": payload.get("passphrase", ""),
        "gpg_library": payload.get("gpg_library", "PGPy"),
        "fingerprint": (payload.get("fingerprint") or _defaults.get("fingerprint", "")).strip(),
        "user_id": (payload.get("user_id") or _defaults.get("user_id", "")).strip(),
        "verify": verify,
    }
    try:
        client = PassboltClient(dict_config=config)
    except PassboltError:
        raise
    except Exception as exc:
        if "Passphrase" in str(exc):
            raise PassboltError("Wrong key passphrase — try again.")
        raise
    if not client.authenticated or not client.user_id:
        raise PassboltError("Authentication failed — check key, passphrase and URL.")
    _client = client
    return {"user_id": client.user_id, "base_url": base_url}


def _children_map(folders: list[dict]) -> dict:
    children: dict = {}
    for f in folders:
        children.setdefault(f.get("folder_parent_id"), []).append(f)
    for lst in children.values():
        lst.sort(key=lambda f: f["name"].lower())
    return children


def _folder_paths(folders: list[dict]) -> dict[str, str]:
    """id → 'Top/Sub/Subsub' full path."""
    by_id = {f["id"]: f for f in folders}
    paths: dict[str, str] = {}

    def path_of(fid: str) -> str:
        if fid in paths:
            return paths[fid]
        f = by_id[fid]
        parent = f.get("folder_parent_id")
        p = f["name"] if not parent or parent not in by_id else path_of(parent) + "/" + f["name"]
        paths[fid] = p
        return p

    for f in folders:
        path_of(f["id"])
    return paths


def api_data(_payload: dict) -> dict:
    if _client is None:
        raise PassboltError("Not connected.")
    folders = _client.get_folders(with_permissions=True)
    users = _client.get_active_users()
    groups = _client.get_groups_list()
    return {
        "groups": [{"id": g["id"], "name": g.get("name", "")} for g in groups],
        "folders": [
            {"id": f["id"], "name": f["name"], "parent": f.get("folder_parent_id")}
            for f in folders
        ],
        "users": [
            {
                "id": u["id"],
                "username": u.get("username", ""),
                "name": (
                    f"{(u.get('profile') or {}).get('first_name', '')} "
                    f"{(u.get('profile') or {}).get('last_name', '')}"
                ).strip(),
            }
            for u in users
        ],
    }


def api_create(payload: dict) -> dict:
    if _client is None:
        raise PassboltError("Not connected.")
    name = payload["name"].strip()
    parent_ids = payload["parent_ids"]
    inherit = bool(payload.get("inherit", True))
    skip_existing = bool(payload.get("skip_existing", True))
    if not name or not parent_ids:
        raise PassboltError("Folder name and at least one parent are required.")

    folders = _client.get_folders()
    by_id = {f["id"]: f for f in folders}
    existing_names: dict[str | None, set[str]] = {}
    for f in folders:
        existing_names.setdefault(f.get("folder_parent_id"), set()).add(f["name"].lower())

    lines, created, skipped, failed = [], 0, 0, 0
    for parent_id in parent_ids:
        parent_name = by_id.get(parent_id, {}).get("name", parent_id)
        if skip_existing and name.lower() in existing_names.get(parent_id, set()):
            lines.append(f"SKIP  {parent_name}/{name} — already exists")
            skipped += 1
            continue
        try:
            new_folder = _client.create_folder(name, parent_id)
            copied = 0
            if inherit:
                fresh_parent = _client.get_folder(parent_id)
                copied = _client.copy_parent_permissions(fresh_parent, new_folder["id"])
            lines.append(
                f"OK    {parent_name}/{name} created"
                + (f" ({copied} permissions inherited)" if inherit else "")
            )
            created += 1
        except PassboltError as exc:
            lines.append(f"FAIL  {parent_name}/{name} — {exc}")
            failed += 1
    lines.append(f"Done: {created} created, {skipped} skipped, {failed} failed.")
    return {"lines": lines}


def api_apply(payload: dict) -> dict:
    if _client is None:
        raise PassboltError("Not connected.")
    user_ids: list[str] = payload.get("user_ids", [])
    group_ids: list[str] = payload.get("group_ids", [])
    folder_ids: list[str] = payload["folder_ids"]
    ptype = int(payload["ptype"])
    recurse = bool(payload.get("recurse", False))
    if (not user_ids and not group_ids) or not folder_ids or ptype not in PERMISSION_LABELS:
        raise PassboltError("Users/groups, folders and a valid permission type are required.")

    folders = _client.get_folders()
    by_id = {f["id"]: f for f in folders}
    children: dict[str | None, list[str]] = {}
    for f in folders:
        children.setdefault(f.get("folder_parent_id"), []).append(f["id"])

    if recurse:
        expanded, seen = [], set()

        def add(fid):
            if fid in seen:
                return
            seen.add(fid)
            expanded.append(fid)
            for child in children.get(fid, []):
                add(child)

        for fid in folder_ids:
            add(fid)
        folder_ids = expanded

    label = PERMISSION_LABELS[ptype]
    targets = [("User", uid) for uid in user_ids] + [("Group", gid) for gid in group_ids]
    lines, done, unchanged, failed = [], 0, 0, 0
    for fid in folder_ids:
        fname = by_id.get(fid, {}).get("name", fid)
        for aro, aro_id in targets:
            try:
                outcome = _client.set_aro_permission(fid, aro, aro_id, ptype)
                if outcome == "unchanged":
                    lines.append(f"SKIP  {fname} · {aro} {aro_id} — already '{label}'")
                    unchanged += 1
                else:
                    lines.append(f"OK    {fname} · {aro} {aro_id} — {outcome} ('{label}')")
                    done += 1
            except PassboltError as exc:
                lines.append(f"FAIL  {fname} · {aro} {aro_id} — {exc}")
                failed += 1
    lines.append(f"Done: {done} applied, {unchanged} unchanged, {failed} failed.")
    return {"lines": lines}


def api_clone(payload: dict) -> dict:
    if _client is None:
        raise PassboltError("Not connected.")
    source_id = payload["source_id"]
    dest_name = payload["dest_name"].strip()
    copy_root_perms = bool(payload.get("copy_root_perms", True))
    if not source_id or not dest_name:
        raise PassboltError("A source folder and the new folder name are required.")

    folders = _client.get_folders(with_permissions=True)
    by_id = {f["id"]: f for f in folders}
    if source_id not in by_id:
        raise PassboltError("Source folder not found — refresh and retry.")
    children: dict[str | None, list[dict]] = {}
    for f in folders:
        children.setdefault(f.get("folder_parent_id"), []).append(f)
    for lst in children.values():
        lst.sort(key=lambda f: f["name"].lower())

    if any(f["name"].lower() == dest_name.lower() for f in children.get(None, [])):
        raise PassboltError(f"A top-level folder named '{dest_name}' already exists.")

    lines: list[str] = []
    created = failed = 0

    dest_root = _client.create_folder(dest_name, None)
    created += 1
    if copy_root_perms:
        n = _client.copy_parent_permissions(by_id[source_id], dest_root["id"])
        lines.append(f"OK    {dest_name} created ({n} permissions copied from source root)")
    else:
        lines.append(f"OK    {dest_name} created")

    def clone_level(src_parent_id: str, dest_parent_id: str, path: str):
        nonlocal created, failed
        for child in children.get(src_parent_id, []):
            try:
                new_folder = _client.create_folder(child["name"], dest_parent_id)
                n = _client.copy_parent_permissions(child, new_folder["id"])
                lines.append(f"OK    {path}/{child['name']} ({n} permissions)")
                created += 1
                clone_level(child["id"], new_folder["id"], f"{path}/{child['name']}")
            except PassboltError as exc:
                lines.append(f"FAIL  {path}/{child['name']} — {exc} (subtree skipped)")
                failed += 1

    clone_level(source_id, dest_root["id"], dest_name)
    lines.append(f"Done: {created} folders created, {failed} failed. Passwords were not touched.")
    return {"lines": lines}


PERM_WORDS = {
    "read": 1, "r": 1, "1": 1,
    "update": 7, "write": 7, "rw": 7, "readwrite": 7, "7": 7,
    "owner": 15, "own": 15, "15": 15,
}


def api_csv_import(payload: dict) -> dict:
    """Create a folder structure (with optional permissions) from CSV rows:
    path,user_or_group,permission — replicated under each selected target."""
    import csv as csv_mod
    import io

    if _client is None:
        raise PassboltError("Not connected.")
    csv_text = (payload.get("csv_text") or "").strip()
    targets: list = payload.get("target_ids") or [None]  # None = Passbolt root
    dry_run = bool(payload.get("dry_run", True))
    if not csv_text:
        raise PassboltError("Paste or load a CSV first.")

    # Tolerate comma or semicolon (Excel in many locales exports ';').
    delimiter = ";" if csv_text.splitlines()[0].count(";") > csv_text.splitlines()[0].count(",") else ","
    rows = list(csv_mod.reader(io.StringIO(csv_text), delimiter=delimiter))
    if rows and rows[0] and rows[0][0].strip().lower() == "path":
        rows = rows[1:]  # header row

    # Collect ordered unique paths (parents before children) + permissions per path.
    ordered_paths: list[str] = []
    perms_by_path: dict[str, list[tuple[str, int]]] = {}

    def add_path(p: str):
        parts = [seg.strip() for seg in p.replace("\\", "/").split("/") if seg.strip()]
        for i in range(1, len(parts) + 1):
            sub = "/".join(parts[:i])
            if sub not in perms_by_path:
                perms_by_path[sub] = []
                ordered_paths.append(sub)
        return "/".join(parts)

    for lineno, row in enumerate(rows, start=2 if len(rows) < len(csv_text.splitlines()) else 1):
        if not row or not row[0].strip():
            continue
        full = add_path(row[0])
        who = row[1].strip() if len(row) > 1 else ""
        perm_word = row[2].strip().lower() if len(row) > 2 else ""
        if who:
            ptype = PERM_WORDS.get(perm_word or "read")
            if ptype is None:
                raise PassboltError(
                    f"CSV line {lineno}: unknown permission '{perm_word}' "
                    "(use read / update / owner)."
                )
            perms_by_path[full].append((who, ptype))

    if not ordered_paths:
        raise PassboltError("No paths found in the CSV.")

    # Resolve users/groups once.
    users = {u["username"].lower(): u for u in _client.get_active_users()}
    groups = {g["name"].lower(): g for g in _client.get_groups_list()}

    def resolve(who: str):
        if "@" in who:
            u = users.get(who.lower())
            return ("User", u["id"]) if u else None
        g = groups.get(who.lower())
        return ("Group", g["id"]) if g else None

    folders = _client.get_folders()
    children = _children_map(folders)
    by_id = {f["id"]: f for f in folders}

    lines: list[str] = []
    created = shared = skipped = failed = 0
    prefix = "PLAN  " if dry_run else ""

    for target in targets:
        tname = by_id[target]["name"] if target and target in by_id else "(root)"
        # name(lower) → id map per parent, updated as we create
        id_by_path: dict[str, str | None] = {"": target}
        existing: dict[str | None, dict[str, str]] = {}
        for pid, kids in children.items():
            existing[pid] = {k["name"].lower(): k["id"] for k in kids}

        for path in ordered_paths:
            parent_path = "/".join(path.split("/")[:-1])
            name = path.split("/")[-1]
            parent_id = id_by_path.get(parent_path)
            if parent_path and parent_id is None:
                failed += 1
                continue  # parent failed earlier
            have = existing.get(parent_id, {}).get(name.lower())
            if have:
                id_by_path[path] = have
                lines.append(f"SKIP  {tname}/{path} — exists")
                skipped += 1
            else:
                if dry_run:
                    lines.append(f"PLAN  create {tname}/{path}")
                    id_by_path[path] = f"dry-{path}"
                    created += 1
                else:
                    try:
                        new_folder = _client.create_folder(name, parent_id)
                        id_by_path[path] = new_folder["id"]
                        existing.setdefault(parent_id, {})[name.lower()] = new_folder["id"]
                        lines.append(f"OK    created {tname}/{path}")
                        created += 1
                    except PassboltError as exc:
                        lines.append(f"FAIL  {tname}/{path} — {exc}")
                        id_by_path[path] = None
                        failed += 1
                        continue
            for who, ptype in perms_by_path.get(path, []):
                aro = resolve(who)
                if aro is None:
                    lines.append(f"FAIL  {tname}/{path} — unknown user/group '{who}'")
                    failed += 1
                    continue
                if dry_run:
                    lines.append(
                        f"PLAN  grant {PERMISSION_LABELS[ptype]} to {who} on {tname}/{path}"
                    )
                    shared += 1
                else:
                    try:
                        fid = id_by_path[path]
                        outcome = _client.set_aro_permission(fid, aro[0], aro[1], ptype)
                        lines.append(
                            f"OK    {tname}/{path} · {who} — {outcome} "
                            f"('{PERMISSION_LABELS[ptype]}')"
                        )
                        shared += 1
                    except PassboltError as exc:
                        lines.append(f"FAIL  {tname}/{path} · {who} — {exc}")
                        failed += 1

    verb = "planned" if dry_run else "done"
    lines.append(
        f"{'DRY RUN — nothing changed. ' if dry_run else ''}"
        f"Done: {created} folders + {shared} permissions {verb}, "
        f"{skipped} existing, {failed} failed."
    )
    return {"lines": lines}


def api_report(payload: dict) -> dict:
    """Access report: folder path × user/group × permission, as CSV."""
    if _client is None:
        raise PassboltError("Not connected.")
    filter_type = payload.get("filter_type", "")   # "" | "User" | "Group"
    filter_id = payload.get("filter_id", "")

    folders = _client.get_folders(with_permissions=True)
    paths = _folder_paths(folders)
    users = {u["id"]: u for u in _client.get_active_users()}
    groups = {g["id"]: g for g in _client.get_groups_list()}

    out = ["folder_path,type,name,permission"]
    count = 0
    for f in sorted(folders, key=lambda f: paths[f["id"]].lower()):
        for perm in f.get("permissions") or []:
            aro, aro_id = perm.get("aro"), perm.get("aro_foreign_key")
            if filter_type and (aro != filter_type or aro_id != filter_id):
                continue
            if aro == "User":
                u = users.get(aro_id)
                name = u["username"] if u else aro_id
            else:
                g = groups.get(aro_id)
                name = g["name"] if g else aro_id
            label = PERMISSION_LABELS.get(perm.get("type"), str(perm.get("type")))
            def q(s):
                return '"' + str(s).replace('"', '""') + '"'
            out.append(f"{q(paths[f['id']])},{aro},{q(name)},{label}")
            count += 1
    return {"csv": "\n".join(out) + "\n", "rows": count, "folders": len(folders)}


def api_rename(payload: dict) -> dict:
    """Bulk rename: replace a substring in every matching folder name."""
    if _client is None:
        raise PassboltError("Not connected.")
    search = payload.get("search") or ""
    replace = payload.get("replace") or ""
    dry_run = bool(payload.get("dry_run", True))
    if not search:
        raise PassboltError("Enter the text to search for in folder names.")

    folders = _client.get_folders()
    paths = _folder_paths(folders)
    lines, done, failed = [], 0, 0
    for f in sorted(folders, key=lambda f: paths[f["id"]].lower()):
        if search not in f["name"]:
            continue
        new_name = f["name"].replace(search, replace).strip()
        if not new_name or new_name == f["name"]:
            continue
        if dry_run:
            lines.append(f"PLAN  {paths[f['id']]} → '{new_name}'")
            done += 1
        else:
            try:
                _client.rename_folder(f["id"], new_name)
                lines.append(f"OK    {paths[f['id']]} → '{new_name}'")
                done += 1
            except PassboltError as exc:
                lines.append(f"FAIL  {paths[f['id']]} — {exc}")
                failed += 1
    lines.append(
        f"{'DRY RUN — nothing changed. ' if dry_run else ''}"
        f"Done: {done} renames{' planned' if dry_run else ''}, {failed} failed."
    )
    return {"lines": lines}


def api_move(payload: dict) -> dict:
    """Move folders under a new parent (or to the root)."""
    if _client is None:
        raise PassboltError("Not connected.")
    folder_ids: list[str] = payload.get("folder_ids") or []
    dest = payload.get("dest_id") or None
    if not folder_ids:
        raise PassboltError("Select at least one folder to move.")

    folders = _client.get_folders()
    by_id = {f["id"]: f for f in folders}
    paths = _folder_paths(folders)

    # Guard: destination must not be one of the moved folders or their descendants.
    def ancestors(fid):
        seen = set()
        while fid and fid in by_id:
            seen.add(fid)
            fid = by_id[fid].get("folder_parent_id")
        return seen

    if dest:
        dest_chain = ancestors(dest)
        for fid in folder_ids:
            if fid in dest_chain:
                raise PassboltError(
                    f"Cannot move '{paths.get(fid, fid)}' into itself or its own subtree."
                )

    dest_label = paths.get(dest, "(root)") if dest else "(root)"
    lines, done, failed = [], 0, 0
    for fid in folder_ids:
        label = paths.get(fid, fid)
        try:
            _client.move_folder(fid, dest)
            lines.append(f"OK    {label} → {dest_label}")
            done += 1
        except PassboltError as exc:
            lines.append(f"FAIL  {label} — {exc}")
            failed += 1
    lines.append(f"Done: {done} moved, {failed} failed.")
    return {"lines": lines}


def api_cleanup(payload: dict) -> dict:
    """Find (and optionally delete) folders that contain no subfolders and no
    passwords visible to you. Recursively-empty trees are deleted deepest-first.
    When deleting, an optional folder_ids list restricts deletion to that
    selection (re-validated against the current empty set)."""
    if _client is None:
        raise PassboltError("Not connected.")
    do_delete = bool(payload.get("delete", False))
    only_ids = set(payload.get("folder_ids") or [])

    folders = _client.get_folders()
    resources = _client.get_resources_list()
    paths = _folder_paths(folders)
    children = _children_map(folders)
    has_resource = {r.get("folder_parent_id") for r in resources}

    empty: set[str] = set()

    def is_empty(fid: str) -> bool:
        if fid in has_resource:
            return False
        kids = children.get(fid, [])
        return all(is_empty(k["id"]) for k in kids)

    for f in folders:
        if is_empty(f["id"]):
            empty.add(f["id"])

    ordered = sorted(empty, key=lambda fid: paths[fid].count("/"), reverse=True)
    lines = []
    if not ordered:
        return {"lines": ["No empty folders found."], "empty_ids": []}

    if not do_delete:
        for fid in sorted(empty, key=lambda fid: paths[fid].lower()):
            lines.append(f"EMPTY {paths[fid]}")
        lines.append(
            f"Found {len(empty)} empty folders (no subfolders, no passwords visible "
            "to you). Note: passwords NOT shared with you would be invisible here — "
            "deletion only removes what the server allows."
        )
        return {"lines": lines, "empty_ids": ordered}

    if only_ids:
        not_empty = only_ids - empty
        for fid in not_empty:
            lines.append(f"SKIP  {paths.get(fid, fid)} — no longer empty, not deleted")
        # Only delete a selected folder if its selected subtree is going too;
        # deepest-first order makes a parent empty once its children are gone,
        # but a parent whose child was NOT selected must be skipped.
        ordered = [fid for fid in ordered if fid in only_ids]
        deleted_set: set[str] = set()
        kept: list[str] = []
        for fid in ordered:
            kids = children.get(fid, [])
            if all(k["id"] in deleted_set for k in kids):
                kept.append(fid)
                deleted_set.add(fid)
            else:
                lines.append(
                    f"SKIP  {paths[fid]} — contains an empty subfolder you did not tick"
                )
        ordered = kept

    done = failed = 0
    for fid in ordered:  # deepest first
        try:
            _client.delete_folder(fid)
            lines.append(f"OK    deleted {paths[fid]}")
            done += 1
        except PassboltError as exc:
            lines.append(f"FAIL  {paths[fid]} — {exc}")
            failed += 1
    lines.append(f"Done: {done} deleted, {failed} failed.")
    return {"lines": lines, "empty_ids": []}


ROUTES = {
    "/api/connect": api_connect,
    "/api/data": api_data,
    "/api/create": api_create,
    "/api/apply": api_apply,
    "/api/clone": api_clone,
    "/api/csv-import": api_csv_import,
    "/api/report": api_report,
    "/api/rename": api_rename,
    "/api/move": api_move,
    "/api/cleanup": api_cleanup,
}


# --------------------------------------------------------------------------- #
# HTTP plumbing
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif self.path == "/api/status":
            d = _defaults
            self._json(200, {
                "connected": _client is not None,
                "user_id": getattr(_client, "user_id", None),
                "defaults_error": _defaults_error,
                "defaults": {
                    "base_url": d.get("base_url", ""),
                    "user_id": d.get("user_id", ""),
                    "gpg_library": d.get("gpg_library", ""),
                    "fingerprint": d.get("fingerprint", ""),
                    "key_file": d.get("key_file", ""),
                    "ca_file": d.get("ca_file", ""),
                },
            })
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        handler = ROUTES.get(self.path)
        if handler is None:
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            with _state_lock:
                result = handler(payload)
            self._json(200, result)
        except PassboltError as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            self._json(500, {"error": traceback.format_exc(limit=5)})


# --------------------------------------------------------------------------- #
# Page (vanilla HTML/JS, no external assets)
# --------------------------------------------------------------------------- #

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Passbolt Bulk Tool</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f3f5fa; --card: #ffffff; --border: #e2e7f0;
    --text: #1b2437; --muted: #66758c;
    --accent: #2563eb; --accent-hover: #1d4ed8; --accent-soft: #edf3ff;
    --ok: #16a34a; --err: #dc2626;
    --radius: 12px;
    --shadow: 0 1px 2px rgba(16,24,40,.06), 0 6px 20px -12px rgba(16,24,40,.18);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0d1220; --card: #161d2e; --border: #283349;
      --text: #e3e9f2; --muted: #8b99b0;
      --accent: #3b82f6; --accent-hover: #5f9bff; --accent-soft: #1b2740;
      --ok: #4ade80; --err: #f87171;
      --shadow: 0 1px 2px rgba(0,0,0,.45), 0 8px 24px -14px rgba(0,0,0,.7);
    }
  }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 0 auto; padding: 22px 20px 10px; max-width: 1120px;
         background: var(--bg); color: var(--text); }
  header.app { display: flex; align-items: baseline; gap: 10px; margin-bottom: 16px; }
  header.app .logo { font-size: 22px; }
  header.app h1 { font-size: 20px; margin: 0; letter-spacing: -.02em; }
  header.app .sub { color: var(--muted); font-size: 13px; }
  fieldset { border: 1px solid var(--border); background: var(--card);
             border-radius: var(--radius); box-shadow: var(--shadow);
             margin: 0 0 16px; padding: 4px 14px 12px; }
  legend { font-weight: 650; font-size: 12px; text-transform: uppercase;
           letter-spacing: .07em; color: var(--muted); padding: 0 6px; }
  label { display: inline-flex; align-items: center; gap: 6px; margin: 4px 12px 4px 0; }
  input[type=text], input[type=password], input[type=url], select {
    padding: 7px 10px; border: 1px solid var(--border); border-radius: 8px;
    min-width: 240px; background: var(--bg); color: inherit; font: inherit;
    transition: border-color .15s, box-shadow .15s; }
  input:focus, select:focus { outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent); }
  input[type=file] { color: var(--muted); font-size: 13px; }
  textarea { width: 100%; padding: 8px 10px; border: 1px solid var(--border);
    border-radius: 8px; background: var(--bg); color: inherit; resize: vertical;
    font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  textarea:focus { outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent); }
  hr { border: none; border-top: 1px solid var(--border); margin: 14px 0; }
  code { background: var(--accent-soft); border-radius: 4px; padding: 1px 5px;
    font-size: 12px; }
  .grouprow { font-weight: 600; }
  input[type=checkbox], input[type=radio] { accent-color: var(--accent);
    width: 15px; height: 15px; }
  button { padding: 8px 16px; border: 1px solid transparent; border-radius: 8px;
    cursor: pointer; background: var(--accent); color: #fff; font: inherit;
    font-weight: 600; transition: background .15s, transform .05s; }
  button:hover { background: var(--accent-hover); }
  button:active { transform: translateY(1px); }
  button.secondary { background: transparent; color: var(--muted);
    border-color: var(--border); font-weight: 500; padding: 5px 11px; font-size: 13px; }
  button.secondary:hover { background: var(--accent-soft); color: var(--accent);
    border-color: var(--accent); }
  button:disabled { opacity: .45; cursor: default; transform: none; }
  #connStatus { padding: 3px 12px; border-radius: 999px; font-size: 12px;
    border: 1px solid var(--border); background: var(--bg); color: var(--muted); }
  .tabcard { background: var(--card); border: 1px solid var(--border);
    border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 16px; }
  .tabs { display: flex; gap: 2px; padding: 6px 10px 0; border-bottom: 1px solid var(--border); }
  .tabs button { background: transparent; color: var(--muted); font-weight: 600;
    border: none; border-radius: 8px 8px 0 0; padding: 10px 16px; }
  .tabs button:hover { color: var(--text); background: var(--accent-soft); }
  .tabs button.active { color: var(--accent); box-shadow: inset 0 -2px 0 var(--accent); }
  .panel { display: none; padding: 14px 16px 16px; }
  .panel.active { display: block; }
  .cols { display: flex; gap: 14px; align-items: stretch; }
  .col { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .col > .rowgap { display: flex; align-items: center; flex-wrap: wrap; gap: 6px;
    min-height: 38px; margin: 0 0 6px; }
  .col > .list { flex: 1; }
  .help { color: var(--muted); font-size: 13px; line-height: 1.55;
    background: var(--accent-soft); border-radius: 8px; padding: 10px 12px;
    margin: 2px 0 12px; }
  .list { border: 1px solid var(--border); background: var(--bg); border-radius: 10px;
    height: 320px; overflow: auto; padding: 6px; }
  .tree ul { list-style: none; padding-left: 20px; margin: 0; }
  .tree > ul { padding-left: 0; }
  .tree li { margin: 1px 0; }
  .tree label, .userrow { border-radius: 6px; padding: 2px 6px; margin: 0; }
  .tree label:hover, .userrow:hover { background: var(--accent-soft); }
  .arrow { display: inline-block; width: 16px; cursor: pointer; user-select: none;
           color: var(--muted); text-align: center; }
  .arrow:hover { color: var(--accent); }
  .userrow { display: block; }
  #log { background: #0b1120; border-radius: 10px; padding: 12px 14px; height: 210px;
         overflow: auto; white-space: pre-wrap;
         font: 12px/1.6 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         color: #b8c4d8; }
  #log .ok { color: #4ade80; }
  #log .err { color: #f87171; }
  #log .muted { color: #64748b; }
  .ok { color: var(--ok); } .err { color: var(--err); white-space: pre-wrap; }
  .muted { color: var(--muted); }
  .rowgap { margin: 9px 0; }
  footer { text-align: center; margin: 14px 0 6px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<header class="app">
  <span class="logo">🗝️</span>
  <h1>Passbolt Bulk Tool</h1>
  <span class="sub">bulk folders &amp; permissions</span>
</header>

<fieldset id="connBox">
  <legend>Connection</legend>
  <div class="rowgap">
    <label>Server URL <input type="url" id="c_url" placeholder="https://passbolt.example.com"></label>
    <label>Private key (.asc) <input type="file" id="c_key" accept=".asc,.txt,.key"></label>
    <label>Passphrase <input type="password" id="c_pass"></label>
  </div>
  <div class="rowgap">
    <label>Backend
      <select id="c_backend"><option>PGPy</option><option>gnupg</option></select>
    </label>
    <label>Fingerprint (gnupg only) <input type="text" id="c_fpr" style="min-width:170px"></label>
    <label>Your User ID (JWT servers) <input type="text" id="c_uid" style="min-width:280px"
           placeholder="uuid from /app/users/view/…"></label>
    <label><input type="checkbox" id="c_verify" checked> Verify TLS</label>
    <label>CA cert, optional (.pem/.crt) <input type="file" id="c_ca" accept=".pem,.crt,.cer,.txt"></label>
    <button id="btnConnect" onclick="connect()">Connect</button>
    <span id="connStatus" class="muted">not connected</span>
  </div>
</fieldset>

<div class="tabcard">
<div class="tabs">
  <button id="tabbtn1" class="active" onclick="showTab(1)">1 · Create subfolder everywhere</button>
  <button id="tabbtn2" onclick="showTab(2)">2 · Assign user permissions</button>
  <button id="tabbtn3" onclick="showTab(3)">3 · Clone structure</button>
  <button id="tabbtn4" onclick="showTab(4)">4 · CSV import</button>
  <button id="tabbtn5" onclick="showTab(5)">5 · Report</button>
  <button id="tabbtn6" onclick="showTab(6)">6 · Maintenance</button>
</div>

<div id="tab1" class="panel active">
  <div class="rowgap">
    <label>New subfolder name <input type="text" id="f_name" placeholder="e.g. KE_SAFARICOM_VAD"></label>
    <label><input type="checkbox" id="f_inherit" checked> Inherit parent folder permissions</label>
    <label><input type="checkbox" id="f_skip" checked> Skip if it already exists</label>
  </div>
  <div class="rowgap">
    Create under these top-level folders:
    <button class="secondary" onclick="setAllTop(true)">Select all</button>
    <button class="secondary" onclick="setAllTop(false)">Select none</button>
  </div>
  <div id="topList" class="list"></div>
  <div class="rowgap"><button id="btnCreate" onclick="doCreate()" disabled>Create subfolders</button></div>
</div>

<div id="tab2" class="panel">
  <div class="cols">
    <div class="col">
      <div class="rowgap"><b>Users &amp; groups</b> <input type="text" id="u_filter" placeholder="filter…"
           oninput="renderUsers()" style="min-width:150px"></div>
      <div id="userList" class="list"></div>
    </div>
    <div class="col">
      <div class="rowgap"><b>Folders</b> <span class="muted">(▸ or double-click to expand)</span>
        <button class="secondary" onclick="setAllFolders(false)">Untick all</button>
        <button class="secondary" onclick="expandAll(true)">Expand all</button>
        <button class="secondary" onclick="expandAll(false)">Collapse all</button>
      </div>
      <div id="folderTree" class="list tree"></div>
    </div>
  </div>
  <div class="rowgap">
    Permission:
    <label><input type="radio" name="ptype" value="1" checked> Can read</label>
    <label><input type="radio" name="ptype" value="7"> Can update (read/write)</label>
    <label><input type="radio" name="ptype" value="15"> Owner</label>
    <label><input type="checkbox" id="p_recurse"> Also apply to all subfolders</label>
    <button id="btnApply" onclick="doApply()" disabled>Apply permissions</button>
  </div>
</div>

<div id="tab3" class="panel">
  <div class="rowgap">
    <label>Source root folder
      <select id="cl_source" style="min-width:260px"></select>
    </label>
    <label>New root folder name
      <input type="text" id="cl_dest" placeholder="e.g. 09 CUSTOMERS DR">
    </label>
  </div>
  <div class="rowgap">
    <label><input type="checkbox" id="cl_rootperms" checked>
      Also copy the source root folder's own permissions onto the new root</label>
  </div>
  <p class="muted">Creates a new top-level folder and recreates the source's complete
  subfolder tree inside it, copying each subfolder's access rights (users and groups,
  same permission levels). Passwords are <b>not</b> copied or moved.</p>
  <div class="rowgap"><button id="btnClone" onclick="doClone()" disabled>Clone structure</button></div>
</div>

<div id="tab4" class="panel">
  <div class="help">
    <b>What this tab does:</b> it creates a whole folder structure — and optionally grants
    access — in one go, from a simple spreadsheet, instead of creating each folder and
    sharing it by hand. Write one row per folder, load or paste it below, pick where to
    import, and run it. Keep <b>Dry run</b> ticked first: it shows exactly what would
    happen without changing anything.
  </div>
  <div class="rowgap">
    <label>CSV file <input type="file" id="csv_file" accept=".csv,.txt"></label>
    <label><input type="checkbox" id="csv_dry" checked> Dry run (preview, change nothing)</label>
  </div>
  <textarea id="csv_text" rows="8" spellcheck="false"
    placeholder="path,user_or_group,permission&#10;TopFolder,,&#10;TopFolder/Subfolder1,group-name,read&#10;TopFolder/Subfolder1,user@company.com,update&#10;TopFolder/Subfolder2,,"></textarea>
  <p class="muted">One row per folder — nested paths with <code>/</code> (missing parents are
  created automatically). Columns 2–3 are optional: who gets access (an email = a user,
  anything else = a group name) and their level (<code>read</code> / <code>update</code> /
  <code>owner</code>). Repeat the same path on several rows to grant several people.
  Comma or semicolon separated; a <code>path,...</code> header row is allowed.</p>
  <div class="rowgap">Import under:
    <label><input type="radio" name="csvtarget" value="root" checked> Passbolt root (top level)</label>
    <label><input type="radio" name="csvtarget" value="tops"> these top-level folders:</label>
    <button class="secondary" onclick="setAllCsvTops(true)">all</button>
    <button class="secondary" onclick="setAllCsvTops(false)">none</button>
  </div>
  <div id="csvTops" class="list" style="height:130px"></div>
  <div class="rowgap"><button id="btnImport" onclick="doImport()" disabled>Import CSV</button></div>
</div>

<div id="tab5" class="panel">
  <div class="rowgap">
    <label>Search <input type="text" id="rep_search" placeholder="type to filter users/groups…"
           oninput="renderReportFilter()" style="min-width:220px"></label>
    <label>Scope
      <select id="rep_filter" style="min-width:300px">
        <option value="">Everyone — full access report</option>
      </select>
    </label>
    <button id="btnReport" onclick="doReport()" disabled>Generate &amp; download CSV</button>
  </div>
  <p class="muted">Exports <code>folder_path, type, name, permission</code> for every folder you
  can see — the full access matrix, or filtered to a single user/group ("what can X access?").
  Type in the search box to narrow the dropdown.</p>
</div>

<div id="tab6" class="panel">
  <div class="help">
    <b>What this tab does:</b> housekeeping across the whole folder tree, in bulk.<br>
    · <b>Bulk rename</b> — fix a name everywhere at once (e.g. a customer code that changed):
    every folder whose name contains the search text gets it replaced. Dry run shows the list first.<br>
    · <b>Bulk move</b> — tick folders in the list and move them all under a different parent
    (or to the top level).<br>
    · <b>Empty-folder cleanup</b> — find folders with no subfolders and no passwords, review
    the list, untick anything you want to keep, and delete the rest.
  </div>
  <div class="rowgap"><b>Bulk rename</b> <span class="muted">— replace text in folder names, everywhere</span></div>
  <div class="rowgap">
    <label>Search <input type="text" id="rn_search" style="min-width:170px"></label>
    <label>Replace with <input type="text" id="rn_replace" style="min-width:170px"></label>
    <label><input type="checkbox" id="rn_dry" checked> Dry run</label>
    <button id="btnRename" onclick="doRename()" disabled>Rename</button>
  </div>
  <hr>
  <div class="rowgap"><b>Bulk move</b> <span class="muted">— move ticked folders under a new parent</span></div>
  <div class="rowgap">
    <input type="text" id="mv_filter" placeholder="filter folders…" oninput="renderMoveList()">
    <label>Destination
      <select id="mv_dest" style="min-width:300px"></select>
    </label>
    <button id="btnMove" onclick="doMove()" disabled>Move ticked</button>
  </div>
  <div id="mvList" class="list" style="height:170px"></div>
  <hr>
  <div class="rowgap"><b>Empty-folder cleanup</b> <span class="muted">— folders with no subfolders and no passwords visible to you</span></div>
  <div class="rowgap">
    <button id="btnCleanFind" class="secondary" onclick="doCleanFind()" disabled>Find empty folders</button>
    <button class="secondary" onclick="setAllClean(true)">Tick all</button>
    <button class="secondary" onclick="setAllClean(false)">Untick all</button>
    <button id="btnCleanDel" onclick="doCleanDelete()" disabled>Delete ticked folders…</button>
  </div>
  <div id="cleanList" class="list" style="height:150px; display:none"></div>
</div>
</div>

<fieldset><legend>Log</legend><div id="log"></div></fieldset>

<footer>© Belsis Meletis</footer>

<script>
let FOLDERS = [], USERS = [], GROUPS = [], KEY_TEXT = "", CA_TEXT = "", DEFAULTS = {};
const ALL_BTNS = ["btnCreate","btnApply","btnClone","btnImport","btnReport",
                  "btnRename","btnMove","btnCleanFind","btnCleanDel"];
function enableAll() { ALL_BTNS.forEach(id => document.getElementById(id).disabled = false); }

document.getElementById("c_url").value = localStorage.getItem("pb_url") || "";
document.getElementById("c_backend").value = localStorage.getItem("pb_backend") || "PGPy";
document.getElementById("c_fpr").value = localStorage.getItem("pb_fpr") || "";
document.getElementById("c_uid").value = localStorage.getItem("pb_uid") || "";
CA_TEXT = localStorage.getItem("pb_ca") || "";
if (CA_TEXT) log("CA certificate restored from previous session.");

// Pre-fill from credentials.json (if present) and detect pre-authenticated
// servers (webapp_auto.py).
(async () => {
  try {
    const s = await (await fetch("/api/status")).json();
    DEFAULTS = s.defaults || {};
    if (s.defaults_error) log(s.defaults_error, "err");
    if (!s.connected && (DEFAULTS.base_url || DEFAULTS.key_file)) {
      if (DEFAULTS.base_url) document.getElementById("c_url").value = DEFAULTS.base_url;
      if (DEFAULTS.user_id) document.getElementById("c_uid").value = DEFAULTS.user_id;
      if (DEFAULTS.gpg_library) document.getElementById("c_backend").value = DEFAULTS.gpg_library;
      if (DEFAULTS.fingerprint) document.getElementById("c_fpr").value = DEFAULTS.fingerprint;
      if (DEFAULTS.key_file) log("Private key: from credentials.json (" + DEFAULTS.key_file + ") — no file to choose.");
      if (DEFAULTS.ca_file) log("CA certificate: from credentials.json (" + DEFAULTS.ca_file + ")");
      log("Defaults loaded from credentials.json — type your passphrase and press Connect.", "ok");
      document.getElementById("c_pass").focus();
    }
    if (s.connected) {
      const st = document.getElementById("connStatus");
      st.textContent = "connected ✓ (auto)";
      st.style.color = "var(--ok)";
      st.style.borderColor = "var(--ok)";
      document.getElementById("connBox").style.display = "none";
      log("Already authenticated as user id " + s.user_id, "ok");
      await loadData();
      enableAll();
    }
  } catch (e) { /* server not pre-authenticated */ }
})();
document.getElementById("c_key").addEventListener("change", ev => {
  const file = ev.target.files[0];
  if (!file) return;
  file.text().then(t => { KEY_TEXT = t; log("Key file loaded: " + file.name); });
});
document.getElementById("c_ca").addEventListener("change", ev => {
  const file = ev.target.files[0];
  if (!file) return;
  file.text().then(t => {
    CA_TEXT = t;
    localStorage.setItem("pb_ca", t);  // public cert, safe to persist
    log("CA certificate loaded: " + file.name);
  });
});

function log(msg, cls) {
  const div = document.getElementById("log");
  const line = document.createElement("div");
  if (!cls) {
    if (msg.startsWith("OK") || msg.startsWith("Done")) cls = "ok";
    else if (msg.startsWith("FAIL") || msg.startsWith("ERROR")) cls = "err";
    else if (msg.startsWith("SKIP")) cls = "muted";
  }
  if (cls) line.className = cls;
  line.textContent = msg;
  div.appendChild(line);
  div.scrollTop = div.scrollHeight;
}

async function api(path, payload) {
  const res = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json"},
                                 body: JSON.stringify(payload || {})});
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function showTab(n) {
  for (const i of [1, 2, 3, 4, 5, 6]) {
    document.getElementById("tab" + i).classList.toggle("active", i === n);
    document.getElementById("tabbtn" + i).classList.toggle("active", i === n);
  }
}

async function connect() {
  const btn = document.getElementById("btnConnect");
  const backend = document.getElementById("c_backend").value;
  if (backend === "PGPy" && !KEY_TEXT && !DEFAULTS.key_file) {
    log("Choose your private key file first (or set key_file in credentials.json).", "err");
    return;
  }
  btn.disabled = true;
  document.getElementById("connStatus").textContent = "connecting…";
  try {
    const r = await api("/api/connect", {
      base_url: document.getElementById("c_url").value,
      private_key: KEY_TEXT,
      passphrase: document.getElementById("c_pass").value,
      gpg_library: backend,
      fingerprint: document.getElementById("c_fpr").value,
      user_id: document.getElementById("c_uid").value.trim(),
      verify: document.getElementById("c_verify").checked,
      ca_cert: CA_TEXT,
    });
    if (r.base_url) document.getElementById("c_url").value = r.base_url;
    localStorage.setItem("pb_url", document.getElementById("c_url").value);
    localStorage.setItem("pb_backend", backend);
    localStorage.setItem("pb_fpr", document.getElementById("c_fpr").value);
    localStorage.setItem("pb_uid", document.getElementById("c_uid").value.trim());
    log("Authenticated as user id " + r.user_id, "ok");
    const st = document.getElementById("connStatus");
    st.textContent = "connected ✓";
    st.style.color = "var(--ok)";
    st.style.borderColor = "var(--ok)";
    await loadData();
    enableAll();
  } catch (e) {
    log("Connect failed: " + e.message, "err");
    document.getElementById("connStatus").textContent = "failed";
  } finally { btn.disabled = false; }
}

async function loadData() {
  const r = await api("/api/data");
  FOLDERS = r.folders; USERS = r.users; GROUPS = r.groups || [];
  log("Loaded " + FOLDERS.length + " folders, " + USERS.length + " users, " +
      GROUPS.length + " groups");
  renderTop(); renderTree(); renderUsers(); renderCloneSelect();
  renderCsvTops(); renderReportFilter(); renderMoveList(); renderMoveDest();
}

function folderPath(id) {
  const byId = Object.fromEntries(FOLDERS.map(f => [f.id, f]));
  const parts = [];
  let f = byId[id];
  while (f) { parts.unshift(f.name); f = byId[f.parent]; }
  return parts.join("/");
}

function renderCsvTops() {
  const box = document.getElementById("csvTops");
  box.innerHTML = "";
  for (const f of childrenOf(null)) {
    const lb = document.createElement("label");
    lb.className = "userrow";
    lb.innerHTML = `<input type="checkbox" class="icb" value="${f.id}"> ${esc(f.name)}`;
    box.appendChild(lb);
  }
}
function setAllCsvTops(on) { document.querySelectorAll("input.icb").forEach(cb => cb.checked = on); }

function renderReportFilter() {
  const needle = (document.getElementById("rep_search").value || "").toLowerCase();
  const sel = document.getElementById("rep_filter");
  const keep = sel.value;
  sel.innerHTML = '<option value="">Everyone — full access report</option>';
  for (const g of GROUPS) {
    const label = "Group: " + g.name;
    if (needle && !label.toLowerCase().includes(needle)) continue;
    const o = document.createElement("option");
    o.value = "Group:" + g.id; o.textContent = label;
    sel.appendChild(o);
  }
  for (const u of USERS) {
    const label = "User: " + (u.name ? u.name + " " : "") + "<" + u.username + ">";
    if (needle && !label.toLowerCase().includes(needle)) continue;
    const o = document.createElement("option");
    o.value = "User:" + u.id; o.textContent = label;
    sel.appendChild(o);
  }
  sel.value = keep;
  if (sel.selectedIndex === -1) sel.selectedIndex = 0;
  // With a search term, preselect the first hit so Enter-Generate flows naturally.
  if (needle && sel.options.length > 1) sel.selectedIndex = 1;
}

function renderMoveList() {
  const needle = document.getElementById("mv_filter").value.toLowerCase();
  const box = document.getElementById("mvList");
  const ticked = new Set(checkedValues("mvcb"));
  box.innerHTML = "";
  const items = FOLDERS.map(f => ({id: f.id, path: folderPath(f.id)}))
                       .sort((a, b) => a.path.localeCompare(b.path));
  for (const it of items) {
    if (needle && !it.path.toLowerCase().includes(needle)) continue;
    const lb = document.createElement("label");
    lb.className = "userrow";
    lb.innerHTML = `<input type="checkbox" class="mvcb" value="${it.id}"${ticked.has(it.id) ? " checked" : ""}> ${esc(it.path)}`;
    box.appendChild(lb);
  }
}

function renderMoveDest() {
  const sel = document.getElementById("mv_dest");
  sel.innerHTML = '<option value="">(root — make it a top-level folder)</option>';
  const items = FOLDERS.map(f => ({id: f.id, path: folderPath(f.id)}))
                       .sort((a, b) => a.path.localeCompare(b.path));
  for (const it of items) {
    const o = document.createElement("option");
    o.value = it.id; o.textContent = it.path;
    sel.appendChild(o);
  }
}

function renderCloneSelect() {
  const sel = document.getElementById("cl_source");
  sel.innerHTML = "";
  for (const f of childrenOf(null)) {
    const opt = document.createElement("option");
    opt.value = f.id;
    opt.textContent = f.name;
    sel.appendChild(opt);
  }
}

function childrenOf(pid) {
  return FOLDERS.filter(f => f.parent === pid)
                .sort((a, b) => a.name.localeCompare(b.name));
}

function renderTop() {
  const box = document.getElementById("topList");
  box.innerHTML = "";
  for (const f of childrenOf(null)) {
    const lb = document.createElement("label");
    lb.className = "userrow";
    lb.innerHTML = `<input type="checkbox" class="topcb" value="${f.id}"> ${esc(f.name)}`;
    box.appendChild(lb);
  }
}

function renderTree() {
  const box = document.getElementById("folderTree");
  box.innerHTML = "";
  const build = (pid, depth) => {
    const kids = childrenOf(pid);
    if (!kids.length) return null;
    const ul = document.createElement("ul");
    if (depth > 0) ul.style.display = "none";  // subfolders start collapsed
    for (const f of kids) {
      const li = document.createElement("li");
      const sub = build(f.id, depth + 1);
      const arrow = document.createElement("span");
      arrow.className = "arrow";
      arrow.textContent = sub ? "▸" : "";
      const label = document.createElement("label");
      label.innerHTML = `<input type="checkbox" class="fcb" value="${f.id}"> ${esc(f.name)}`;
      if (sub) {
        arrow.onclick = () => toggleBranch(sub, arrow);
        label.ondblclick = ev => { ev.preventDefault(); toggleBranch(sub, arrow); };
      }
      li.appendChild(arrow);
      li.appendChild(label);
      if (sub) li.appendChild(sub);
      ul.appendChild(li);
    }
    return ul;
  };
  const tree = build(null, 0);
  if (tree) box.appendChild(tree);
}

function toggleBranch(ul, arrow) {
  const open = ul.style.display !== "none";
  ul.style.display = open ? "none" : "";
  arrow.textContent = open ? "▸" : "▾";
}

function expandAll(open) {
  document.querySelectorAll("#folderTree ul ul").forEach(ul => ul.style.display = open ? "" : "none");
  document.querySelectorAll("#folderTree .arrow").forEach(a => {
    if (a.textContent) a.textContent = open ? "▾" : "▸";
  });
}

function renderUsers() {
  const needle = document.getElementById("u_filter").value.toLowerCase();
  const box = document.getElementById("userList");
  const tickedU = new Set(selectedUsers());
  const tickedG = new Set(checkedValues("gcb"));
  box.innerHTML = "";
  for (const g of GROUPS) {
    const label = "👥 " + g.name;
    if (needle && !label.toLowerCase().includes(needle)) continue;
    const lb = document.createElement("label");
    lb.className = "userrow grouprow";
    lb.innerHTML = `<input type="checkbox" class="gcb" value="${g.id}"${tickedG.has(g.id) ? " checked" : ""}> ${esc(label)}`;
    box.appendChild(lb);
  }
  for (const u of USERS) {
    const label = (u.name + " <" + u.username + ">").trim();
    if (needle && !label.toLowerCase().includes(needle)) continue;
    const lb = document.createElement("label");
    lb.className = "userrow";
    lb.innerHTML = `<input type="checkbox" class="ucb" value="${u.id}"${tickedU.has(u.id) ? " checked" : ""}> ${esc(label)}`;
    box.appendChild(lb);
  }
}

const esc = s => s.replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const checkedValues = cls => [...document.querySelectorAll("input." + cls + ":checked")].map(i => i.value);
const selectedUsers = () => checkedValues("ucb");
function setAllTop(on) { document.querySelectorAll("input.topcb").forEach(cb => cb.checked = on); }
function setAllFolders(on) { document.querySelectorAll("input.fcb").forEach(cb => cb.checked = on); }

async function doCreate() {
  const name = document.getElementById("f_name").value.trim();
  const parents = checkedValues("topcb");
  if (!name) { log("Enter the subfolder name.", "err"); return; }
  if (!parents.length) { log("Tick at least one top-level folder.", "err"); return; }
  const btn = document.getElementById("btnCreate");
  btn.disabled = true;
  log("Creating '" + name + "' under " + parents.length + " folder(s)…");
  try {
    const r = await api("/api/create", {
      name, parent_ids: parents,
      inherit: document.getElementById("f_inherit").checked,
      skip_existing: document.getElementById("f_skip").checked,
    });
    r.lines.forEach(l => log(l, l.startsWith("FAIL") ? "err" : ""));
    await loadData();
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

async function doClone() {
  const sel = document.getElementById("cl_source");
  const sourceId = sel.value;
  const sourceName = sel.options[sel.selectedIndex] ? sel.options[sel.selectedIndex].textContent : "";
  const destName = document.getElementById("cl_dest").value.trim();
  if (!sourceId) { log("Pick a source root folder.", "err"); return; }
  if (!destName) { log("Enter the new root folder name.", "err"); return; }
  if (!confirm(`Clone the structure of '${sourceName}' (${countSubtree(sourceId)} subfolders) ` +
               `into a new root folder '${destName}'?\nPasswords are not copied.`)) return;
  const btn = document.getElementById("btnClone");
  btn.disabled = true;
  log(`Cloning '${sourceName}' → '${destName}' …`);
  try {
    const r = await api("/api/clone", {
      source_id: sourceId, dest_name: destName,
      copy_root_perms: document.getElementById("cl_rootperms").checked,
    });
    r.lines.forEach(l => log(l, l.startsWith("FAIL") ? "err" : ""));
    await loadData();
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

function countSubtree(id) {
  let n = 0;
  for (const child of FOLDERS.filter(f => f.parent === id)) n += 1 + countSubtree(child.id);
  return n;
}

document.getElementById("csv_file").addEventListener("change", ev => {
  const file = ev.target.files[0];
  if (!file) return;
  file.text().then(t => {
    document.getElementById("csv_text").value = t;
    log("CSV loaded: " + file.name + " (" + t.split(/\r?\n/).filter(l => l.trim()).length + " lines)");
  });
});

async function doImport() {
  const csvText = document.getElementById("csv_text").value.trim();
  if (!csvText) { log("Paste or load a CSV first.", "err"); return; }
  const dry = document.getElementById("csv_dry").checked;
  const underTops = document.querySelector("input[name=csvtarget]:checked").value === "tops";
  let targets = [];
  if (underTops) {
    targets = checkedValues("icb");
    if (!targets.length) { log("Tick at least one top-level folder (or choose root).", "err"); return; }
  }
  if (!dry && !confirm("Execute the CSV import for real" +
      (underTops ? ` under ${targets.length} top folder(s)` : " at the root") +
      "?\nTip: run it as a dry run first.")) return;
  const btn = document.getElementById("btnImport");
  btn.disabled = true;
  log(dry ? "CSV dry run …" : "CSV import …");
  try {
    const r = await api("/api/csv-import", {csv_text: csvText, target_ids: targets, dry_run: dry});
    r.lines.forEach(l => log(l, l.startsWith("PLAN") ? "muted" : ""));
    if (!dry) await loadData();
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

async function doReport() {
  const v = document.getElementById("rep_filter").value;
  const [ftype, fid] = v ? v.split(":") : ["", ""];
  const btn = document.getElementById("btnReport");
  btn.disabled = true;
  log("Generating access report …");
  try {
    const r = await api("/api/report", {filter_type: ftype, filter_id: fid});
    const blob = new Blob([r.csv], {type: "text/csv;charset=utf-8"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "passbolt-access-report.csv";
    a.click();
    URL.revokeObjectURL(a.href);
    log(`OK    report downloaded — ${r.rows} permission rows across ${r.folders} folders`);
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

async function doRename() {
  const search = document.getElementById("rn_search").value;
  const replace = document.getElementById("rn_replace").value;
  const dry = document.getElementById("rn_dry").checked;
  if (!search) { log("Enter the text to search for.", "err"); return; }
  if (!dry && !confirm(`Rename folders for real: replace '${search}' with '${replace}' everywhere?`)) return;
  const btn = document.getElementById("btnRename");
  btn.disabled = true;
  try {
    const r = await api("/api/rename", {search, replace, dry_run: dry});
    r.lines.forEach(l => log(l, l.startsWith("PLAN") ? "muted" : ""));
    if (!dry) await loadData();
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

async function doMove() {
  const ids = checkedValues("mvcb");
  const dest = document.getElementById("mv_dest").value || null;
  const destLabel = dest ? folderPath(dest) : "(root)";
  if (!ids.length) { log("Tick at least one folder to move.", "err"); return; }
  if (!confirm(`Move ${ids.length} folder(s) under '${destLabel}'?`)) return;
  const btn = document.getElementById("btnMove");
  btn.disabled = true;
  try {
    const r = await api("/api/move", {folder_ids: ids, dest_id: dest});
    r.lines.forEach(l => log(l));
    await loadData();
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

function setAllClean(on) { document.querySelectorAll("input.clcb").forEach(cb => cb.checked = on); }

async function doCleanFind() {
  const btn = document.getElementById("btnCleanFind");
  btn.disabled = true;
  try {
    const r = await api("/api/cleanup", {delete: false});
    r.lines.filter(l => !l.startsWith("EMPTY")).forEach(l => log(l));
    const box = document.getElementById("cleanList");
    box.innerHTML = "";
    const items = r.empty_ids.map(id => ({id, path: folderPath(id)}))
                             .sort((a, b) => a.path.localeCompare(b.path));
    for (const it of items) {
      const lb = document.createElement("label");
      lb.className = "userrow";
      lb.innerHTML = `<input type="checkbox" class="clcb" value="${it.id}" checked> ${esc(it.path)}`;
      box.appendChild(lb);
    }
    box.style.display = items.length ? "" : "none";
    if (items.length) log(`Review the list below — untick anything to keep, then press 'Delete ticked folders…'.`);
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

async function doCleanDelete() {
  const ids = checkedValues("clcb");
  if (!ids.length) {
    log("Run 'Find empty folders' first and tick the ones to delete.", "err");
    return;
  }
  const typed = prompt(
    `You are about to permanently delete ${ids.length} folder(s).\n` +
    `This cannot be undone.\n\nType DELETE to confirm:`);
  if (!typed || typed.trim().toLowerCase() !== "delete") {
    log("Cleanup cancelled — nothing deleted.");
    return;
  }
  const btn = document.getElementById("btnCleanDel");
  btn.disabled = true;
  try {
    const r = await api("/api/cleanup", {delete: true, folder_ids: ids});
    r.lines.forEach(l => log(l));
    document.getElementById("cleanList").style.display = "none";
    document.getElementById("cleanList").innerHTML = "";
    await loadData();
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}

async function doApply() {
  const users = selectedUsers();
  const groups = checkedValues("gcb");
  const folders = checkedValues("fcb");
  const ptype = document.querySelector("input[name=ptype]:checked").value;
  if (!users.length && !groups.length) { log("Tick at least one user or group.", "err"); return; }
  if (!folders.length) { log("Tick at least one folder.", "err"); return; }
  const labels = {1: "can read", 7: "can update", 15: "owner"};
  const who = [groups.length && groups.length + " group(s)", users.length && users.length + " user(s)"]
              .filter(Boolean).join(" + ");
  if (!confirm(`Grant '${labels[ptype]}' to ${who} on ${folders.length} folder(s)` +
               (document.getElementById("p_recurse").checked ? " + their subfolders" : "") + "?")) return;
  const btn = document.getElementById("btnApply");
  btn.disabled = true;
  log("Applying permissions…");
  try {
    const r = await api("/api/apply", {
      user_ids: users, group_ids: groups, folder_ids: folders, ptype: Number(ptype),
      recurse: document.getElementById("p_recurse").checked,
    });
    r.lines.forEach(l => log(l, l.startsWith("FAIL") ? "err" : ""));
  } catch (e) { log("ERROR: " + e.message, "err"); }
  finally { btn.disabled = false; }
}
</script>
</body>
</html>
"""


def main():
    server = None
    for port in range(PORT, PORT + 20):
        try:
            server = ThreadingHTTPServer((HOST, port), Handler)
            break
        except OSError:
            print(f"Port {port} busy, trying {port + 1} …")
    if server is None:
        raise SystemExit(f"No free port found in {PORT}-{PORT + 19}.")
    url = f"http://{HOST}:{server.server_address[1]}"
    print(f"Passbolt Bulk Tool running at {url}  (Ctrl-C to stop)")
    threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
