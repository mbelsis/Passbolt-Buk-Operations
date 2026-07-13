# Passbolt Bulk Tool

A small, self-contained local web tool for **bulk folder and permission operations**
against a [Passbolt](https://www.passbolt.com) server — the operations that are safe but
painfully slow to do one-by-one in the Passbolt web interface.

It runs entirely on your machine (`127.0.0.1` only), talks to your Passbolt server with
your own account and OpenPGP key, and **never reads, copies, or re-shares passwords** —
every operation works on folders and their access rights only.

---

## Capabilities

The UI has six tabs. Every destructive operation supports a **dry run** and/or an
explicit confirmation, and every run prints a per-item `OK / SKIP / FAIL` report in the
log pane.

### 1 · Create subfolder everywhere
Type a name (e.g. a new customer code) and tick which top-level folders to target — the
subfolder is created under each of them in one run.
- *Inherit parent folder permissions* (default on): copies each parent's access rights
  onto the new subfolder — without this, a folder created via the API is visible only to
  its creator, because the Passbolt **server** never cascades permissions (the browser
  extension normally does it client-side).
- *Skip if it already exists*: makes the operation safe to re-run.

### 2 · Assign user & group permissions
- Left: filterable list of **groups** (marked 👥, listed first) and **users** — tick any mix.
- Right: the folder tree, collapsed to top level — click ▸ or double-click to expand,
  tick any combination of folders and subfolders (Expand all / Collapse all / Untick all).
- Choose the level — *can read* / *can update (read-write)* / *owner* — optionally
  *also apply to all subfolders*, confirm, apply.
- Existing permissions are upgraded/downgraded to the chosen level; already-correct ones
  are skipped; other users' permissions are untouched.

### 3 · Clone structure
Pick a source root folder and a name for a **new** root folder: the source's complete
subfolder tree is recreated inside it, and each cloned subfolder receives **the same
access rights** (users and groups, same levels) as its original. Optionally the source
root's own permissions are copied onto the new root as well. Ideal for standing up a new
environment (e.g. a DR copy of the PRD tree). Passwords are not copied or moved.

### 4 · CSV import
Build a whole structure — with optional per-folder access — from a spreadsheet:

```csv
path,user_or_group,permission
TopFolder,,
TopFolder/Subfolder1,group-name,read
TopFolder/Subfolder1,user@company.com,update
TopFolder/Subfolder2,,
```

- One row per folder; nested paths use `/` and missing parents are created automatically.
- Columns 2–3 are optional: who gets access (an **email = user**, anything else =
  **group name**) and the level (`read` / `update` / `owner`). Repeat a path on several
  rows to grant several people.
- Comma **or semicolon** separated (Excel-friendly); a `path,...` header row is allowed.
- Target: the Passbolt root, **or replicated under several ticked top-level folders at
  once** (create the same customer structure under PRD + STG + DR in one run).
- **Dry run is on by default** — it prints the complete plan (`PLAN create…`,
  `PLAN grant…`) without changing anything.

### 5 · Report (access matrix export)
One click downloads `passbolt-access-report.csv` with
`folder_path, type, name, permission` for every folder you can see — your audit /
compliance snapshot. Use the search box + dropdown to filter to a single user or group
(*"what can X access?"* — e.g. for offboarding reviews).

### 6 · Maintenance
- **Bulk rename** — replace text in folder names everywhere (e.g. a customer code that
  changed). Dry run lists every affected folder with its new name first.
- **Bulk move** — filterable list of all folders by full path: tick any set, pick a new
  parent (or the root), move them all. Guarded against moving a folder into its own
  subtree.
- **Empty-folder cleanup** — *Find empty folders* lists every folder with no subfolders
  and no passwords *visible to you* (including chains of nested empty folders) as a
  tickable list. Untick anything you want to keep, then *Delete ticked folders…* — which
  requires you to literally type `DELETE` — removes the rest, deepest-first. A ticked
  parent is skipped if one of its empty children was left unticked.

---

## Two ways to run it

Both entry points serve **the exact same application** — same six tabs, same features,
same engine (`webapp_auto.py` simply imports `webapp.py`). They differ **only in how you
authenticate at startup**; anything added to the tool is automatically available in both.

| | `webapp.py` (manual) | `webapp_auto.py` (auto-connect) |
|---|---|---|
| How you authenticate | Connection form in the browser | Reads `credentials.json` + OS credential store, connects at startup |
| Passphrase | Typed into the page (memory only) | OS credential store / env var / prompt |
| Best for | First use, occasional use | Regular use — zero typing |

With a `credentials.json` in place, even `webapp.py` becomes **passphrase-only**: the
form is pre-filled and the key/CA are read from the configured paths.

---

## Requirements

- **Python 3.9+** (no GUI toolkit needed — the UI runs in your web browser)
- Network access to your Passbolt server
- **Your Passbolt OpenPGP private key** (armored `.asc`). Export from the Passbolt
  browser extension: *avatar → Profile → Keys inspector → Export private key* (the
  "account recovery kit" is the same file).
- Your key **passphrase**
- If the server uses a company-internal CA or a TLS-inspection proxy (Zscaler/Netskope):
  the **CA certificate** (`.pem`/`.crt`). Export from Keychain Access / certmgr, or:

  ```bash
  openssl s_client -connect your-passbolt-host:443 -showcerts </dev/null 2>/dev/null \
    | awk '/BEGIN CERT/,/END CERT/' > passbolt-chain.pem
  ```

Python packages (installed below): `py-passbolt`, `keyring`.

### Passbolt server compatibility

- **Both auth schemes**: legacy GPGAuth (Passbolt ≤ v4) is tried first, with automatic
  fallback to JWT (v5+). JWT servers additionally need your **User ID** (UUID): in the
  Passbolt web app go to *Users → click your own name* — the URL ends in
  `/app/users/view/<your-user-id>`.
- Accounts with **enforced MFA** may be refused API login — use an account without MFA
  enforcement or a dedicated automation user.
- Passbolt has **no API keys** by design (end-to-end encryption: the key *is* the
  credential); the auto-connect launcher is the equivalent convenience.

---

## Installation (once)

```bash
cd passbolt-bulk-tool
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Create your config file from the template:

```bash
cp credentials.json.example.json credentials.json
```

```json
{
  "base_url": "https://passbolt.example.com",
  "key_file": "~/Documents/passbolt-recovery-kit.asc",
  "ca_file": "",
  "user_id": "",
  "gpg_library": "PGPy",
  "fingerprint": "",
  "verify": true
}
```

| Field | Meaning |
|---|---|
| `base_url` | Your Passbolt server. A full web-app URL also works — the path is stripped. |
| `key_file` | Path to your `.asc` private key (`~` is expanded; plain spaces, **no backslash escaping** — this is JSON, not shell). |
| `ca_file` | Path to your CA certificate, or `""` for a publicly trusted cert. |
| `user_id` | Your UUID — only needed on JWT (v5+) servers, else `""`. |
| `gpg_library` | `PGPy` (default). `gnupg` only for exotic keys — needs GnuPG installed, key imported, and `fingerprint` filled. |
| `verify` | `true` = verify TLS (recommended). |

The **passphrase is never stored in this file**. For `webapp_auto.py`, store it once in
the OS credential store — macOS Keychain, Windows Credential Manager, or Linux Secret
Service (GNOME Keyring / KWallet):

```bash
python webapp_auto.py --set-passphrase
```

Lookup order at startup: `PASSBOLT_PASSPHRASE` env var → OS credential store →
interactive prompt (so headless Linux works too).

## Running

```bash
source .venv/bin/activate
python webapp.py        # manual/passphrase-only mode — opens http://127.0.0.1:8765
# or
python webapp_auto.py   # auto-connect mode — opens the UI already authenticated
```

If port 8765 is busy the tool picks the next free port and prints the URL.

---

## Security notes

- The web UI binds to **127.0.0.1 only** — nothing is reachable from the network.
- Key and passphrase go only to the local Python process, held in memory.
- `.gitignore` excludes **all `.json` files** (except the example template), keys
  (`*.asc`), and certificates — secrets can't be committed if you publish this folder.
- Turning *Verify TLS* off works around certificate errors but removes MITM protection —
  prefer providing the CA certificate.

## How Passbolt sharing actually works (why some options exist)

- The Passbolt **server never cascades permissions** — the browser extension does it
  client-side. This tool replicates that: *inherit parent permissions* on creation, and
  *apply to subfolders* on grants.
- All operations are **folder-only**. Passwords already inside a folder keep their
  current sharing (re-sharing a resource requires re-encrypting its secret per user —
  deliberately out of scope). Resources added later via the web UI pick up folder
  permissions on creation.
- Permission levels: *can read* = 1, *can update* = 7, *owner* = 15.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` | Internal CA / TLS-inspection proxy — provide the CA cert (form field or `ca_file`). |
| `did not return Passbolt JSON` | Wrong base URL — check the hostname. |
| `Wrong key passphrase` | Exactly that — retype it. |
| `This server uses JWT authentication…` | Fill in your User ID (see compatibility above). |
| `credentials.json is invalid JSON and was IGNORED` | Usually backslash-escaped paths — write plain spaces. |
| Empty grey window from `app.py` | macOS system Tk 8.5 is broken — use `webapp.py`. |
| Port in use | The tool picks the next free port automatically and prints the URL. |

## Files

- `webapp.py` — the web UI (manual / passphrase-only mode)
- `webapp_auto.py` — same UI, auto-connects from `credentials.json` + OS credential store
- `passbolt_client.py` — API client: [py-passbolt](https://github.com/passbolt/lab-passbolt-py)
  extended with folder CRUD, `/share/folder` permission management, move/rename/delete,
  and JWT auth fallback
- `credentials.json.example.json` — configuration template
- `app.py` — legacy Tkinter desktop UI (requires Tk 8.6+; not usable with macOS system Python)
- `LICENSE.md` — license terms

## License

Free for **non-commercial use with attribution** to the creator, **Belsis Meletis** —
provided **"as is"**, with no warranty and no liability, direct or indirect, for any
damages arising from its use. See [LICENSE.md](LICENSE.md) for the full terms.

---

© Belsis Meletis
