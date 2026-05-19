# SecureChat

End-to-end encrypted chat: **Python TCP server** (stores ciphertext) + **Flask web client** (browser UI). The web app opens its own TCP connection to the server so every browser session can log in and chat independently.

---

## 1. One virtual environment (use for server and client)

From the **project root** (`1securechat/`):

```bash
# Create venv once (skip if `venv/` already exists)
python3 -m venv venv

# Activate (macOS / Linux)
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

**Windows (PowerShell):** `.\venv\Scripts\Activate.ps1`  
**Windows (cmd):** `venv\Scripts\activate.bat`

Keep this same activated shell for installs; use **two terminals** both activated the same way to run server and client together.

---

## 2. Start the **server** (must be running first)

In **terminal A** (project root, venv activated):

```bash
source venv/bin/activate
cd server
python3 server.py
```

You should see:

- `Server listening on 0.0.0.0:12345...`
- `UDP Discovery Listener started on port 12346`

Leave this process running. User accounts and messages live in **`server/server_database.db`** (always this path, no matter which directory you start Python from).

**If your prompt already shows you are inside `server/`** (e.g. `... server %`), do **not** run `cd server` again, and activate the venv from the parent folder:

```bash
source ../venv/bin/activate
python3 server.py
```

---

## 3. Start the **web client** (connects to the server)

In **terminal B** (project root, venv activated):

```bash
source venv/bin/activate
cd client
python3 web_app.py
```

Default URL: **http://127.0.0.1:5001**

The Flask process opens a **TCP** connection to the chat server (default **127.0.0.1:12345**). It tries **localhost first** (fast), **this machine’s LAN IP**, and **UDP discovery** in parallel, then **retries a few times** if the server is still starting—no extra configuration for same-machine / same-Wi‑Fi use.

If discovery or LAN guesses fail (unusual), set ``SECURECHAT_TCP_HOST`` (see below).

**If the UI stays “Offline”** (same machine): start **`server.py` first**, then the web app. If the TCP server is on **another host** or UDP broadcast is blocked (VPN, Docker, some Wi‑Fi), point the client at it:

```bash
export SECURECHAT_TCP_HOST=192.168.x.x   # IP of the machine running server.py
# optional: export SECURECHAT_TCP_PORT=12345
# optional: export SECURECHAT_SKIP_DISCOVERY=1   # skip UDP wait
python3 web_app.py
```

On **Docker Desktop (Mac)**, the host is often `host.docker.internal` from inside a container.

Optional custom web port:

```bash
python3 web_app.py 8080
```

Then open **http://127.0.0.1:8080**.

**If you are already inside `client/`:** `source ../venv/bin/activate` then `python3 web_app.py`.

---

## 4. Quick copy-paste summary

Use your **real** project path (example: `~/Desktop/1securechat`). **Put each command on its own line** — if you paste `source …/activate` and `cd …` on the same line without a newline, the shell will fail (`activatecd`, `cd: no such file or directory`).

**Terminal A (server):**

```bash
cd ~/Desktop/1securechat
source venv/bin/activate
cd server && python3 server.py
```

**Terminal B (web app):**

```bash
cd ~/Desktop/1securechat
source venv/bin/activate
cd client && python3 web_app.py
```

**Browser:** http://127.0.0.1:5001

---

## 5. Optional: production-style secret for Flask

The web app uses Flask sessions (CSRF). Set a strong secret in **terminal B** before starting:

```bash
export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 web_app.py
```

---

## 6. Smoke test (no browser)

With the **server** running:

```bash
source venv/bin/activate
cd /path/to/1securechat
python3 test_e2e.py
```

---

## 7. Troubleshooting

| Issue | What to check |
|--------|----------------|
| **Old account “doesn’t exist” / login always fails** | The server now always uses **`server/server_database.db`**. If you registered users while the DB lived at the **repo root** (`1securechat/server_database.db`), copy it: `cp server_database.db server/server_database.db` (from project root). |
| Wrong password or **TOTP** | TOTP is time-based — fix device clock; use the current 6-digit code from the same app you set up at registration. |
| **Too many login attempts** | Wait about one minute (server rate limit), then try again. |
| Web shows “Offline” / cannot register | Start **`server.py` before** `web_app.py`. The server sends a tiny **`SERVER_READY`** frame right after TCP accept so the client can confirm the link. Check port **12345** (TCP). Set **`SECURECHAT_TCP_HOST`** if needed. See §3. |
| Firewall | Allow inbound **12345** (TCP) and **12346** (UDP) if clients are on another host. |
| Wrong Python | Use `python3` and the same `venv` for both processes. |

---

## 8. Project layout (short)

| Path | Role |
|------|------|
| `server/server.py` | TCP chat server + UDP discovery |
| `server/database.py` | SQLite users/messages |
| `client/web_app.py` | Flask UI + bridge to TCP server |
| `client/templates/index.html` | Main UI |
| `shared/crypto.py` | AES/RSA helpers |

---

## 9. Roles (RBAC)

Everyone registers the same way: **Sign up** → set up authenticator (QR) → verify → **Sign in** with username, password, and 6-digit code.

**Master admin (one-time):** The **first** account registered with username `admin` receives the `master_admin` role. If a master admin already exists, no one else can register as `admin` (sign in instead).

**Roles:**

| Role | Capabilities |
|------|----------------|
| `user` | Chat, groups, own message delete |
| `moderator` | User features + delete any DM/group message + view user list |
| `master_admin` | Full user management: assign `user` / `moderator`, delete accounts (not master admin) |

After login as master admin, open **Administration** (shield icon) in the chats header.

---

## 10. Tkinter desktop client (optional)

If you use the older GUI:

```bash
source venv/bin/activate
cd client
python3 app.py
```

Same rule: **start the server first.**






f (venv) is wrong or broken, reset and activate from the root:

cd ~/Desktop/1securechat
source venv/bin/activate
cd client
python3 web_app.py
Do not run source venv/bin/activate inside client/ — there is no client/venv/.

For the TCP server (other terminal), from the project root:


cd ~/Desktop/1securechat
source venv/bin/activate
cd server
python3 server.py
