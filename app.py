"""Passbolt Bulk Tool — small Tkinter GUI for bulk folder + permission operations.

Features
  1. Create a subfolder with a given name under every (or selected) top-level
     folder, optionally inheriting each parent folder's permissions.
  2. Grant one or more users read / read-write / owner permission on any
     selection of folders and subfolders, optionally recursing into children.

Run:  python3 app.py
"""

from __future__ import annotations

import json
import os
import queue
import threading
import traceback
from pathlib import Path

# Must be set before the Tk interpreter starts (macOS system Tk).
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from passbolt_client import (
    PERMISSION_LABELS,
    PERMISSION_OWNER,
    PERMISSION_READ,
    PERMISSION_UPDATE,
    PassboltClient,
    PassboltError,
)

CONFIG_FILE = Path(__file__).parent / "config.json"

CHECKED, UNCHECKED = "☑", "☐"  # ☑ ☐


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Passbolt Bulk Tool")
        self.geometry("1000x760")

        # macOS system Tk opens windows behind everything else without focus;
        # briefly pin on top, then release.
        self.lift()
        self.attributes("-topmost", True)
        self.after(700, lambda: self.attributes("-topmost", False))
        self.focus_force()

        self.client: PassboltClient | None = None
        self.folders: list[dict] = []          # raw folder records
        self.folders_by_id: dict[str, dict] = {}
        self.children: dict[str | None, list[dict]] = {}
        self.users: list[dict] = []

        self.log_queue: queue.Queue[str] = queue.Queue()
        self.busy = False

        self._build_connection_frame()
        self._build_notebook()
        self._build_log()
        self._load_saved_config()
        self.after(150, self._drain_log_queue)

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #

    def _build_connection_frame(self):
        frame = ttk.LabelFrame(self, text="Connection")
        frame.pack(fill="x", padx=10, pady=(10, 5))

        self.var_url = tk.StringVar()
        self.var_keyfile = tk.StringVar()
        self.var_passphrase = tk.StringVar()
        self.var_backend = tk.StringVar(value="PGPy")
        self.var_fingerprint = tk.StringVar()
        self.var_verify_tls = tk.BooleanVar(value=True)

        row1 = ttk.Frame(frame)
        row1.pack(fill="x", padx=8, pady=3)
        ttk.Label(row1, text="Server URL:").pack(side="left")
        ttk.Entry(row1, textvariable=self.var_url).pack(
            side="left", fill="x", expand=True, padx=(5, 15)
        )
        ttk.Checkbutton(row1, text="Verify TLS", variable=self.var_verify_tls).pack(side="left")

        row2 = ttk.Frame(frame)
        row2.pack(fill="x", padx=8, pady=3)
        ttk.Label(row2, text="Private key file:").pack(side="left")
        ttk.Entry(row2, textvariable=self.var_keyfile).pack(
            side="left", fill="x", expand=True, padx=5
        )
        ttk.Button(row2, text="Browse…", command=self._browse_key).pack(side="left")

        row3 = ttk.Frame(frame)
        row3.pack(fill="x", padx=8, pady=3)
        ttk.Label(row3, text="Passphrase:").pack(side="left")
        ttk.Entry(row3, textvariable=self.var_passphrase, show="•", width=28).pack(
            side="left", padx=(5, 15)
        )
        ttk.Label(row3, text="GPG backend:").pack(side="left")
        ttk.Combobox(
            row3, textvariable=self.var_backend, values=["PGPy", "gnupg"],
            width=8, state="readonly",
        ).pack(side="left", padx=(5, 15))
        ttk.Label(row3, text="Fingerprint (gnupg only):").pack(side="left")
        ttk.Entry(row3, textvariable=self.var_fingerprint, width=24).pack(side="left", padx=5)

        row4 = ttk.Frame(frame)
        row4.pack(fill="x", padx=8, pady=(3, 8))
        self.btn_connect = ttk.Button(row4, text="Connect", command=self.connect)
        self.btn_connect.pack(side="left")
        self.btn_refresh = ttk.Button(
            row4, text="Refresh folders/users", command=self.refresh_data, state="disabled"
        )
        self.btn_refresh.pack(side="left", padx=8)
        self.lbl_status = ttk.Label(row4, text="Not connected", foreground="grey")
        self.lbl_status.pack(side="left", padx=10)

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        self._build_tab_create()
        self._build_tab_permissions()

    def _build_tab_create(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="1 · Create subfolder everywhere")

        top = ttk.Frame(tab)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text="New subfolder name:").pack(side="left")
        self.var_new_name = tk.StringVar()
        ttk.Entry(top, textvariable=self.var_new_name, width=32).pack(side="left", padx=6)

        self.var_inherit = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            top, text="Inherit parent folder permissions", variable=self.var_inherit
        ).pack(side="left", padx=12)
        self.var_skip_existing = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            top, text="Skip if it already exists", variable=self.var_skip_existing
        ).pack(side="left")

        mid = ttk.LabelFrame(tab, text="Create under these top-level folders")
        mid.pack(fill="both", expand=True, padx=8, pady=4)

        btns = ttk.Frame(mid)
        btns.pack(fill="x", padx=4, pady=2)
        ttk.Button(btns, text="Select all", command=lambda: self._set_all_top(True)).pack(side="left")
        ttk.Button(btns, text="Select none", command=lambda: self._set_all_top(False)).pack(
            side="left", padx=6
        )

        self.tree_top = ttk.Treeview(mid, show="tree", selectmode="none")
        self.tree_top.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree_top.bind("<Button-1>", lambda e: self._toggle_check(self.tree_top, e))

        bottom = ttk.Frame(tab)
        bottom.pack(fill="x", padx=8, pady=6)
        self.btn_create = ttk.Button(
            bottom, text="Create subfolders", command=self.run_create, state="disabled"
        )
        self.btn_create.pack(side="left")

    def _build_tab_permissions(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="2 · Assign user permissions")

        panes = ttk.Panedwindow(tab, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=8, pady=6)

        # Users pane
        users_frame = ttk.LabelFrame(panes, text="Users (multi-select)")
        panes.add(users_frame, weight=1)
        self.var_user_filter = tk.StringVar()
        self.var_user_filter.trace_add("write", lambda *_: self._refill_users())
        ttk.Entry(users_frame, textvariable=self.var_user_filter).pack(
            fill="x", padx=4, pady=(4, 2)
        )
        self.list_users = tk.Listbox(users_frame, selectmode="extended", exportselection=False)
        self.list_users.pack(fill="both", expand=True, padx=4, pady=4)

        # Folders pane
        folders_frame = ttk.LabelFrame(panes, text="Folders (click to tick)")
        panes.add(folders_frame, weight=2)
        fbtns = ttk.Frame(folders_frame)
        fbtns.pack(fill="x", padx=4, pady=2)
        ttk.Button(fbtns, text="Untick all", command=self._untick_all_perm).pack(side="left")
        ttk.Button(fbtns, text="Expand all", command=lambda: self._expand_all(True)).pack(
            side="left", padx=6
        )
        ttk.Button(fbtns, text="Collapse all", command=lambda: self._expand_all(False)).pack(
            side="left"
        )
        self.tree_perm = ttk.Treeview(folders_frame, show="tree", selectmode="none")
        self.tree_perm.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree_perm.bind("<Button-1>", lambda e: self._toggle_check(self.tree_perm, e))

        # Options + action
        opts = ttk.Frame(tab)
        opts.pack(fill="x", padx=8, pady=4)
        ttk.Label(opts, text="Permission:").pack(side="left")
        self.var_ptype = tk.IntVar(value=PERMISSION_READ)
        ttk.Radiobutton(opts, text="Can read", variable=self.var_ptype,
                        value=PERMISSION_READ).pack(side="left", padx=4)
        ttk.Radiobutton(opts, text="Can update (read/write)", variable=self.var_ptype,
                        value=PERMISSION_UPDATE).pack(side="left", padx=4)
        ttk.Radiobutton(opts, text="Owner", variable=self.var_ptype,
                        value=PERMISSION_OWNER).pack(side="left", padx=4)

        self.var_recurse = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opts, text="Also apply to all subfolders of ticked folders",
            variable=self.var_recurse,
        ).pack(side="left", padx=16)

        self.btn_apply = ttk.Button(
            opts, text="Apply permissions", command=self.run_apply_permissions, state="disabled"
        )
        self.btn_apply.pack(side="right")

    def _build_log(self):
        frame = ttk.LabelFrame(self, text="Log")
        frame.pack(fill="both", padx=10, pady=(0, 10))
        self.txt_log = tk.Text(frame, height=10, state="disabled", wrap="word")
        self.txt_log.pack(fill="both", expand=True, padx=4, pady=4)

    # ------------------------------------------------------------------ #
    # Config persistence (never stores the passphrase)
    # ------------------------------------------------------------------ #

    def _load_saved_config(self):
        if CONFIG_FILE.exists():
            try:
                cfg = json.loads(CONFIG_FILE.read_text())
                self.var_url.set(cfg.get("base_url", ""))
                self.var_keyfile.set(cfg.get("key_file", ""))
                self.var_backend.set(cfg.get("gpg_library", "PGPy"))
                self.var_fingerprint.set(cfg.get("fingerprint", ""))
                self.var_verify_tls.set(cfg.get("verify", True))
            except (ValueError, OSError) as exc:
                self.log(f"Could not read config.json: {exc}")

    def _save_config(self):
        cfg = {
            "base_url": self.var_url.get().strip(),
            "key_file": self.var_keyfile.get().strip(),
            "gpg_library": self.var_backend.get(),
            "fingerprint": self.var_fingerprint.get().strip(),
            "verify": self.var_verify_tls.get(),
        }
        try:
            CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
        except OSError as exc:
            self.log(f"Could not save config.json: {exc}")

    # ------------------------------------------------------------------ #
    # Logging / threading plumbing
    # ------------------------------------------------------------------ #

    def log(self, message: str):
        self.log_queue.put(message)

    def _drain_log_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.txt_log.configure(state="normal")
                self.txt_log.insert("end", message + "\n")
                self.txt_log.see("end")
                self.txt_log.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(150, self._drain_log_queue)

    def _run_in_thread(self, target, done_message: str | None = None):
        if self.busy:
            messagebox.showinfo("Busy", "Another operation is still running.")
            return
        self.busy = True
        self._set_buttons("disabled")

        def wrapper():
            try:
                target()
                if done_message:
                    self.log(done_message)
            except PassboltError as exc:
                self.log(f"ERROR: {exc}")
            except Exception:
                self.log("UNEXPECTED ERROR:\n" + traceback.format_exc())
            finally:
                self.busy = False
                self.after(0, lambda: self._set_buttons("normal"))

        threading.Thread(target=wrapper, daemon=True).start()

    def _set_buttons(self, state: str):
        connected = self.client is not None
        self.btn_connect.configure(state=state)
        for btn in (self.btn_refresh, self.btn_create, self.btn_apply):
            btn.configure(state=state if connected else "disabled")

    # ------------------------------------------------------------------ #
    # Connect / refresh
    # ------------------------------------------------------------------ #

    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select your Passbolt private key",
            filetypes=[("PGP keys", "*.asc *.txt *.key"), ("All files", "*")],
        )
        if path:
            self.var_keyfile.set(path)

    def connect(self):
        url = self.var_url.get().strip().rstrip("/")
        key_file = self.var_keyfile.get().strip()
        passphrase = self.var_passphrase.get()
        backend = self.var_backend.get()

        if not url:
            messagebox.showerror("Missing", "Server URL is required.")
            return
        if backend == "PGPy" and not key_file:
            messagebox.showerror("Missing", "Private key file is required for the PGPy backend.")
            return
        if backend == "gnupg" and not self.var_fingerprint.get().strip():
            messagebox.showerror(
                "Missing",
                "Key fingerprint is required for the gnupg backend "
                "(and the key must be imported in your local gpg keyring).",
            )
            return

        config = {
            "base_url": url,
            "passphrase": passphrase,
            "gpg_library": backend,
            "fingerprint": self.var_fingerprint.get().strip(),
            "verify": self.var_verify_tls.get(),
        }
        if key_file:
            try:
                config["private_key"] = Path(key_file).read_text()
            except OSError as exc:
                messagebox.showerror("Key file", f"Cannot read key file: {exc}")
                return

        def do_connect():
            self.log(f"Connecting to {url} …")
            client = PassboltClient(dict_config=config)
            if not client.authenticated or not client.user_id:
                raise PassboltError(
                    "Authentication failed — check the key, passphrase and server URL."
                )
            self.client = client
            self.log(f"Authenticated as user id {client.user_id}")
            self._load_data()
            self.after(0, self._save_config)
            self.after(0, lambda: self.lbl_status.configure(
                text=f"Connected · {url}", foreground="green"))

        self._run_in_thread(do_connect, done_message="Ready.")

    def refresh_data(self):
        self._run_in_thread(self._load_data, done_message="Folders and users refreshed.")

    def _load_data(self):
        assert self.client is not None
        self.log("Loading folders …")
        folders = self.client.get_folders(with_permissions=True)
        self.log(f"  {len(folders)} folders")
        self.log("Loading users …")
        users = self.client.get_active_users()
        self.log(f"  {len(users)} active users")

        self.folders = folders
        self.folders_by_id = {f["id"]: f for f in folders}
        children: dict[str | None, list[dict]] = {}
        for f in folders:
            children.setdefault(f.get("folder_parent_id"), []).append(f)
        for lst in children.values():
            lst.sort(key=lambda f: f.get("name", "").lower())
        self.children = children
        self.users = users

        self.after(0, self._refill_trees)
        self.after(0, self._refill_users)

    # ------------------------------------------------------------------ #
    # Tree helpers (checkbox emulation)
    # ------------------------------------------------------------------ #

    def _refill_trees(self):
        # Tab 1: top-level folders only
        self.tree_top.delete(*self.tree_top.get_children())
        for f in self.children.get(None, []):
            self.tree_top.insert("", "end", iid=f["id"], text=f"{UNCHECKED} {f['name']}")

        # Tab 2: full tree
        self.tree_perm.delete(*self.tree_perm.get_children())

        def insert(parent_iid, parent_id):
            for f in self.children.get(parent_id, []):
                self.tree_perm.insert(
                    parent_iid, "end", iid=f["id"], text=f"{UNCHECKED} {f['name']}"
                )
                insert(f["id"], f["id"])

        insert("", None)

    def _toggle_check(self, tree: ttk.Treeview, event) -> None:
        # Only toggle when the click lands on the item text, not the expander.
        if "indicator" in tree.identify("element", event.x, event.y):
            return
        iid = tree.identify_row(event.y)
        if not iid:
            return
        text = tree.item(iid, "text")
        if text.startswith(UNCHECKED):
            tree.item(iid, text=CHECKED + text[1:])
        elif text.startswith(CHECKED):
            tree.item(iid, text=UNCHECKED + text[1:])

    def _checked_ids(self, tree: ttk.Treeview) -> list[str]:
        result = []

        def walk(iid):
            for child in tree.get_children(iid):
                if tree.item(child, "text").startswith(CHECKED):
                    result.append(child)
                walk(child)

        walk("")
        return result

    def _set_all_top(self, checked: bool):
        mark = CHECKED if checked else UNCHECKED
        for iid in self.tree_top.get_children(""):
            text = self.tree_top.item(iid, "text")
            self.tree_top.item(iid, text=mark + text[1:])

    def _untick_all_perm(self):
        def walk(iid):
            for child in self.tree_perm.get_children(iid):
                text = self.tree_perm.item(child, "text")
                self.tree_perm.item(child, text=UNCHECKED + text[1:])
                walk(child)

        walk("")

    def _expand_all(self, open_: bool):
        def walk(iid):
            for child in self.tree_perm.get_children(iid):
                self.tree_perm.item(child, open=open_)
                walk(child)

        walk("")

    def _refill_users(self):
        needle = self.var_user_filter.get().lower().strip()
        self.list_users.delete(0, "end")
        self._visible_users = []
        for user in self.users:
            profile = user.get("profile") or {}
            label = (
                f"{profile.get('first_name', '')} {profile.get('last_name', '')}"
                f" <{user.get('username', '')}>"
            ).strip()
            if needle and needle not in label.lower():
                continue
            self._visible_users.append(user)
            self.list_users.insert("end", label)

    # ------------------------------------------------------------------ #
    # Operation 1: create subfolder under every selected top folder
    # ------------------------------------------------------------------ #

    def run_create(self):
        name = self.var_new_name.get().strip()
        if not name:
            messagebox.showerror("Missing", "Enter the subfolder name to create.")
            return
        parent_ids = self._checked_ids(self.tree_top)
        if not parent_ids:
            messagebox.showerror("Missing", "Tick at least one top-level folder.")
            return
        inherit = self.var_inherit.get()
        skip_existing = self.var_skip_existing.get()

        def do_create():
            assert self.client is not None
            created = skipped = failed = 0
            for parent_id in parent_ids:
                parent = self.folders_by_id[parent_id]
                existing = [
                    f for f in self.children.get(parent_id, [])
                    if f["name"].lower() == name.lower()
                ]
                if existing and skip_existing:
                    self.log(f"SKIP  {parent['name']}/{name} — already exists")
                    skipped += 1
                    continue
                try:
                    new_folder = self.client.create_folder(name, parent_id)
                    copied = 0
                    if inherit:
                        # Re-read the parent to get fresh permissions.
                        fresh_parent = self.client.get_folder(parent_id)
                        copied = self.client.copy_parent_permissions(
                            fresh_parent, new_folder["id"]
                        )
                    self.log(
                        f"OK    {parent['name']}/{name} created"
                        + (f" ({copied} permissions inherited)" if inherit else "")
                    )
                    created += 1
                except PassboltError as exc:
                    self.log(f"FAIL  {parent['name']}/{name} — {exc}")
                    failed += 1
            self.log(f"Done: {created} created, {skipped} skipped, {failed} failed.")
            self._load_data()

        self._run_in_thread(do_create)

    # ------------------------------------------------------------------ #
    # Operation 2: assign permissions
    # ------------------------------------------------------------------ #

    def run_apply_permissions(self):
        selected_indices = self.list_users.curselection()
        if not selected_indices:
            messagebox.showerror("Missing", "Select at least one user.")
            return
        users = [self._visible_users[i] for i in selected_indices]

        folder_ids = self._checked_ids(self.tree_perm)
        if not folder_ids:
            messagebox.showerror("Missing", "Tick at least one folder.")
            return

        ptype = self.var_ptype.get()
        recurse = self.var_recurse.get()

        if recurse:
            expanded: list[str] = []
            seen: set[str] = set()

            def add_with_children(fid):
                if fid in seen:
                    return
                seen.add(fid)
                expanded.append(fid)
                for child in self.children.get(fid, []):
                    add_with_children(child["id"])

            for fid in folder_ids:
                add_with_children(fid)
            folder_ids = expanded

        label = PERMISSION_LABELS[ptype]
        summary = (
            f"Grant '{label}' to {len(users)} user(s) on {len(folder_ids)} folder(s)?"
        )
        if not messagebox.askyesno("Confirm", summary):
            return

        def do_apply():
            assert self.client is not None
            done = unchanged = failed = 0
            for fid in folder_ids:
                fname = self.folders_by_id.get(fid, {}).get("name", fid)
                for user in users:
                    uname = user.get("username", user["id"])
                    try:
                        outcome = self.client.set_user_permission(fid, user["id"], ptype)
                        if outcome == "unchanged":
                            self.log(f"SKIP  {fname} · {uname} — already '{label}'")
                            unchanged += 1
                        else:
                            self.log(f"OK    {fname} · {uname} — {outcome} ('{label}')")
                            done += 1
                    except PassboltError as exc:
                        self.log(f"FAIL  {fname} · {uname} — {exc}")
                        failed += 1
            self.log(f"Done: {done} applied, {unchanged} unchanged, {failed} failed.")

        self._run_in_thread(do_apply)


if __name__ == "__main__":
    App().mainloop()
