# Passbolt Bulk Tool

A small, self-contained local web tool for **bulk folder and permission operations**
against a [Passbolt](https://www.passbolt.com) server — the operations that are safe but
painfully slow to do one-by-one in the Passbolt web interface.

It runs entirely on your machine (`127.0.0.1` only), talks to your Passbolt server with
your own account and OpenPGP key. Every operation works on folders and their access
rights only — it **never reads, copies, or re-shares passwords**, with one opt-in
exception: *Also copy the passwords inside* on **Clone structure** (off by default).

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
environment (e.g. a DR copy of the PRD tree).
- *Also copy the passwords inside* (off by default): every password in the source tree is
  duplicated into the matching new folder and shared with **the same users and groups at
  the same levels**. The secret is decrypted locally with your key and re-encrypted for
  each person who gets access (group members included); Passbolt v5 encrypted metadata is
  re-encrypted with the shared metadata key. Copies are **independent** — changing the
  original later does not change the copy. The originals are never moved or modified.
  You can only copy passwords you can decrypt, and on v5 the shared metadata key must
  have been shared with your account.
- *Dry run* (on by default) prints the plan — every folder and password with its number
  of permissions — without creating anything and without reading any secret.
- A subfolder whose permissions fail to copy is still created and cloned into, with a
  `FAIL` line saying its permissions were not copied. A password whose sharing fails is
  deleted again, so no unshared duplicate is left behind.
- You become **owner of every copy** (Passbolt makes the creator owner), even where you
  had less access on the original.

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

## Choose how to install it: Python or Docker

Both run **the same tool on your own machine only** (`127.0.0.1`) — pick whichever is
easier for you. Neither is a server for other people: the tool has no login of its own.

| | **Option A · Python** | **Option B · Docker** |
|---|---|---|
| You need | Python 3.9+ | Docker Desktop (or Docker Engine) |
| Install | `venv` + `pip install` ([below](#installation-once--option-a--python)) | `docker compose up -d --build` ([below](#option-b--docker)) |
| Pinned, tested library versions | You manage the venv | Built in (`constraints.txt`) |
| Auto-connect (`webapp_auto.py`, passphrase from Keychain) | ✅ | — (type the passphrase in the page) |
| Opens the browser for you | ✅ | — (open http://127.0.0.1:8765) |
| Private key | Chosen in the page, or `key_file` in `credentials.json` | Chosen in the page, or placed in `./keys` |

## Two ways to connect (Option A · Python)

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
- **JWT sessions renew themselves**: access tokens are short-lived, so when the server
  answers 401 the tool uses the refresh token (single-use; the next one arrives as a
  cookie) and retries the request. If the refresh is refused it logs in again with your
  key; only if that also fails does the operation stop with *"session expired … —
  reconnect"*. Long runs (e.g. cloning a large tree with passwords) are not cut off.
- **Passbolt v5 encrypted metadata** is supported where the tool reads password names
  (Clone with passwords). v5 *encrypted folders* (off by default in Passbolt 5) are not.
- Accounts with **enforced MFA** may be refused API login — use an account without MFA
  enforcement or a dedicated automation user.
- Passbolt has **no API keys** by design (end-to-end encryption: the key *is* the
  credential); the auto-connect launcher is the equivalent convenience.

---

## Installation (once) — Option A · Python

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
| `user_id` | Your UUID — only needed on JWT (v5+) servers, else `""`. Hover the **?** next to *Your User ID* in the page for where to find it (Passbolt → *Users* → click your own name → the address bar ends in `/app/users/view/<your-user-id>`). |
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

## Option B · Docker

The image contains only the tool's code — never a key, passphrase, certificate or
`credentials.json` (`.dockerignore` keeps them out of the build). It runs as a non-root
user and is published on **127.0.0.1 only**.

```bash
cd passbolt-bulk-tool
cp .env.example .env        # optional: pre-fill server URL, User ID, key and CA paths
docker compose up -d --build
```

Open **http://127.0.0.1:8765**, type your passphrase and press **Connect**.

- **Private key / CA certificate** — either choose them in the Connection form, or copy
  them into a `keys/` folder next to `docker-compose.yml` (git-ignored, mounted
  read-only) and set the paths *as seen inside the container* in `.env`:
  `PASSBOLT_KEY_FILE=/keys/passbolt-recovery-kit.asc`, `PASSBOLT_CA_FILE=/keys/company-ca.pem`.
- **Server URL and User ID** — `PASSBOLT_BASE_URL` and `PASSBOLT_USER_ID` in `.env`, or
  type them in the form.
- The **passphrase** is always typed in the page; it is never put in `.env` or the image.
- Stop it with `docker compose down`; update after pulling new code with
  `docker compose up -d --build`.

> ⚠️ Keep the port mapping as `127.0.0.1:8765:8765`. Publishing it as `8765:8765` exposes
> the tool — and whichever Passbolt account is connected in it — to your whole network.

Without Compose:

```bash
docker build -t passbolt-bulk-tool:local .
docker run --rm -p 127.0.0.1:8765:8765 passbolt-bulk-tool:local
```

Run the test suite inside the image:

```bash
docker run --rm -v "$PWD/tests:/app/tests:ro" passbolt-bulk-tool:local \
  python -m unittest discover -s tests -v
```

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
- All operations are **folder-only**, except the opt-in password copy of Clone structure.
  Passwords already inside a folder keep their current sharing (re-sharing an existing
  resource requires re-encrypting its secret per user — out of scope). Resources added
  later via the web UI pick up folder permissions on creation.
- Copying passwords reads every secret in the source tree. If your Passbolt server
  records action logs, each copy shows up there as a secret access by your account.
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
| Port in use | The tool picks the next free port automatically and prints the URL. In Docker, change the left side of the mapping, e.g. `127.0.0.1:8766:8765`. |
| Docker: `Private key file not found: /keys/…` | The file isn't in `./keys`, or `PASSBOLT_KEY_FILE` uses the host path — use the path inside the container (`/keys/<file>`), or choose the key in the form. |
| Docker: server name doesn't resolve / connection refused | The container uses Docker's DNS. On a VPN, check `docker run --rm passbolt-bulk-tool:local python -c "import socket; print(socket.gethostbyname('your-passbolt-host'))"`; if it fails, add the host under `extra_hosts:` in `docker-compose.yml`. |

## Files

- `webapp.py` — the web UI (manual / passphrase-only mode)
- `webapp_auto.py` — same UI, auto-connects from `credentials.json` + OS credential store
- `passbolt_client.py` — API client: [py-passbolt](https://github.com/passbolt/lab-passbolt-py)
  extended with folder CRUD, `/share/folder` permission management, move/rename/delete,
  JWT auth fallback, and password copying (secret re-encryption, `/share/resource`,
  v5 metadata keys)
- `tests/` — run with `.venv/bin/python -m unittest discover -s tests -v`; a fake
  Passbolt server with real PGP keys:
  - `test_clone.py` — Clone structure, including password copies (v4 and v5 metadata)
  - `test_jwt_session.py` — JWT login fallback, token refresh, re-login, "reconnect" error
- `credentials.json.example.json` — configuration template (Option A)
- `Dockerfile`, `docker-compose.yml`, `.env.example`, `.dockerignore` — Option B
- `requirements.txt` + `constraints.txt` — dependencies and the exact tested versions
- `app.py` — legacy Tkinter desktop UI (requires Tk 8.6+; not usable with macOS system Python)
- `LICENSE.md` — license terms

## License

Free for **non-commercial use with attribution** to the creator, **Belsis Meletis** —
provided **"as is"**, with no warranty and no liability, direct or indirect, for any
damages arising from its use. See [LICENSE.md](LICENSE.md) for the full terms.

---

© Belsis Meletis
