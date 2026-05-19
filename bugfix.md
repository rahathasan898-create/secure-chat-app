# SecureChat — Bugfix log

Problems encountered while building and revamping this project, and how each was fixed.  
Use this as a handoff for debugging similar issues later.

---

## 1. Message delete not real-time (sender only)

**Symptoms**

- Deleting a message updated the UI for the person who deleted it, not the other participant.
- Deleted messages sometimes stayed visible until a full reload.

**Cause**

1. **UI polling** only re-rendered the message list when `messages.length` **increased** (`>`), so deletes (shorter list) never triggered a refresh.
2. **Server** removed the row in SQLite but did not notify the peer’s TCP session; the receiver’s in-memory `messages_by_peer` was unchanged.

**Fix**

- **`client/templates/index.html`**: Compare length with `!==` so decreases trigger re-render.
- **`server/database.py`**: `get_message_participants(message_id)` to find sender/receiver before delete.
- **`server/server.py`**: After successful delete, push `{ action: 'MSG_DELETED', message_id, with_user }` to the other user if online.
- **`client/web_app.py`**: Handle `MSG_DELETED`; update thread preview after delete.

---

## 2. Seeing yourself in the contact list / texting yourself

**Symptoms**

- Logged-in user appeared in “People” and online strip.
- Could start a chat with yourself.

**Cause**

1. **`renderContacts`** filtered with `currentState.username`, but **`pollState` updated `currentState.username` only after rendering**, so the filter often saw `null` and showed everyone.
2. No server-side guard on self-DM.

**Fix**

- Pass **`state.username`** from the current poll into `renderContacts(..., myUsername)`.
- **`/api/status`**: Exclude self from `all_users`, `online_users`, `contacts`; clear invalid `target_user == me`.
- **`/api/start_chat`**, **`/api/send_message`**, **`server.py`** (`GET_KEY`, `SEND_MSG`, `GET_MESSAGES`): Reject when target is self.
- **`index.html`**: `addContact()` already blocked self; extended list rendering.

---

## 3. Two SQLite databases (users “disappear” after login)

**Symptoms**

- Registered on one run; login failed or “user not found” on the next.
- Two files: `server/server_database.db` and repo-root `server_database.db`.

**Cause**

- DB path was **relative to current working directory**, so starting `server.py` from different folders created/used different files.

**Fix**

- **`server/database.py`**: `DEFAULT_DB_PATH` = absolute path next to the module (`server/server_database.db`).
- **README**: Troubleshooting + optional `cp` from old root DB.

---

## 4. README / terminal path confusion

**Symptoms**

- `source: no such file or directory: venv/bin/activate` when already in `client/`.
- `cd: no such file or directory: /path/to/1securechat` (placeholder left in docs).
- Merged shell lines (`activatecd`, `cd serverpython3`) from paste errors.

**Cause**

- **`venv/`** lives at **project root**, not under `client/`.
- README used a fake path; commands pasted without newlines.

**Fix**

- **From `client/`**: `source ../venv/bin/activate` then `python3 web_app.py`.
- **From root**: `source venv/bin/activate`, then `cd server` or `cd client`.
- README §4 uses `~/Desktop/1securechat` and warns: **one command per line**.

---

## 5. Web UI stuck on “Connecting…” / “Offline” (post–group chat)

**Symptoms**

- Flask terminal sometimes showed `[Network] Connected to 127.0.0.1:12345` but the browser stayed on Connecting/Offline.
- Flask access log had `GET /` but **no** `GET /api/status`.

**Cause (main — introduced with group chat UI)**

- While adding **Groups** + `renderGroupsList()`, the line **`async function pollState() {`** was **deleted** by mistake.
- The polling body was left as orphan `try { ... }` code → **`pollState` undefined** → JavaScript error on load → status never polled.

**Other contributing issues (fixed in the same period)**

| Issue | Fix |
|--------|-----|
| `network.connect()` before `sessions[id]` existed | Register session dict **before** `connect()`; ignore `SERVER_READY` in callback before session check |
| UDP discovery blocked localhost for ~3s | Try **127.0.0.1** first; discovery in **background thread**; multi-round retry |
| No visible TCP error | Status badge shows error + `tcp_loopback_open` probe in `/api/status` |
| TCP handshake deadlock risk | Server sends **`SERVER_READY`** immediately after accept |

**Fix (summary)**

- **`client/templates/index.html`**: Restore `async function pollState() { ... }`.
- **`client/web_app.py`**: Session order; `ensure_network()` from `/api/status` when disconnected.
- **`client/network.py`**: Smarter host order, retries, optional `SECURECHAT_TCP_HOST`.
- **`server/server.py`**: `SERVER_READY` on connect.

**Verify**

- Browser hard refresh (`Cmd+Shift+R`).
- Flask log should show **`GET /api/status`** every ~1s.
- `curl`/urllib to `/api/status` → `"connected": true` when server is up.

---

## 6. Logout left a dead TCP client

**Symptoms**

- After logout, login/register did nothing until page reload.

**Cause**

- Old `NetworkClient` was closed with reconnect disabled; state still referenced it.

**Fix**

- **`client/web_app.py`**: On logout, create a new `NetworkClient`, new callback, `connect()` in background; reset session fields.

---

## 7. Race in `GET_ALL_USERS` / success handling (`web_app.py`)

**Symptoms**

- Roster or success responses mishandled; some branches unreachable.

**Cause**

- Overlapping `elif` branches for `GET_KEY`, generic `success`, and `all_users`.

**Fix**

- Merge/reorder handling so `GET_KEY`, history, groups, `all_users`, and delete success each have clear branches.

---

## 8. Concurrent Flask requests vs session state

**Symptoms**

- Rare garbled UI or inconsistent `messages` / roster under load.

**Cause**

- Multiple threads (poll + TCP listener) mutating `sessions[sid]` without coordination.

**Fix**

- Per-session **`threading.Lock`** around state reads/writes in handlers and `/api/status`.

---

## 9. Group chat feature (context, not a single bug)

**Added**

- Tables: `groups`, `group_members`, `group_key_wraps`, `group_messages`.
- TCP: `CREATE_GROUP`, `GET_MY_GROUPS`, `GET_GROUP_MESSAGES`, `SEND_GROUP_MSG`, `DELETE_GROUP_MESSAGE`, `RECEIVE_GROUP_MSG`, `GROUP_MSG_DELETED`.
- Shared group AES key, RSA-wrapped per member at create time.
- UI: Groups list, create modal, `chat_mode` `dm` | `group`.

**Lesson**

- Large UI edits should be followed by a quick **JS syntax check** and confirming **`/api/status`** appears in Flask logs.

---

## Quick verification checklist

| Check | Expected |
|--------|----------|
| `cd server && python3 server.py` | `Server listening on 0.0.0.0:12345...` |
| `cd client && python3 web_app.py` | `Running on http://127.0.0.1:5001` |
| Open app + hard refresh | Badge **Connected**; log shows `/api/status` |
| `python3 test_e2e.py` (server running) | `ALL TESTS PASSED` |
| Delete message (two users online) | Both UIs remove message without reload |
| Contact list | Your username **not** listed |

---

## Files most often touched for these fixes

| File | Role |
|------|------|
| `client/templates/index.html` | UI, polling, contacts/groups rendering |
| `client/web_app.py` | Flask API, session state, TCP message routing |
| `client/network.py` | TCP connect, discovery, reconnect |
| `server/server.py` | TCP protocol, push notifications |
| `server/database.py` | SQLite path, groups schema, message delete |
| `README.md` | Run instructions and troubleshooting |

---

*Last updated: May 2026 — covers work through group chat revamp and connection/pollState fixes.*
