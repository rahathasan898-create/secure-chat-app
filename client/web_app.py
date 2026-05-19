import sys
import os
import socket
import base64
import secrets
import threading
import uuid
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template, session

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from client.network import NetworkClient
from shared.crypto import CryptoUtils

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server')))
from rbac import permissions_for_role, normalize_role

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or 'dev-only-change-FLASK_SECRET_KEY-in-production'

sessions = {}


@app.before_request
def _ensure_csrf_token():
    if request.endpoint == 'static' or (request.path or '').startswith('/static'):
        return
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.permanent = True


def _require_csrf():
    if request.method != 'POST':
        return None
    token = request.headers.get('X-CSRF-Token', '')
    if token != session.get('csrf_token'):
        return jsonify({'error': 'Invalid or missing CSRF token'}), 403
    return None


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_network(state):
    net = state['network']
    if net.connected or net.reconnecting:
        return
    net.connect(max_rounds=1)
    if not net.connected and not net.reconnecting:
        threading.Thread(target=net.connect, daemon=True).start()


def _append_peer_message(state, peer, entry):
    if peer not in state['messages_by_peer']:
        state['messages_by_peer'][peer] = []
    state['messages_by_peer'][peer].append(entry)


def _append_group_message(state, group_id, entry):
    if group_id not in state['messages_by_group']:
        state['messages_by_group'][group_id] = []
    state['messages_by_group'][group_id].append(entry)


def _bump_group_preview(state, group_id, text):
    if text is None:
        return
    state['_group_preview'][group_id] = (text or '')[:160]


def _bump_preview(state, peer, text):
    if text is None:
        return
    state['_last_preview'][peer] = (text or '')[:160]


def _decrypt_history_row(state, username, row):
    sender = row['sender_username']
    receiver = row['receiver_username']
    enc = base64.b64decode(row['encrypted_content_b64'])
    if sender == username:
        aes = state['aes_keys'].get(receiver)
        if not aes:
            return None
        try:
            text = CryptoUtils.decrypt_aes(aes, enc).decode('utf-8')
            return {
                'sender': 'You',
                'text': text,
                'ts': row['timestamp'],
                'server_id': row['id'],
            }
        except Exception:
            return None
    aes = state['aes_keys'].get(sender)
    if row.get('encrypted_aes_key_b64') and state['private_key']:
        try:
            wrap = base64.b64decode(row['encrypted_aes_key_b64'])
            aes = CryptoUtils.decrypt_rsa(state['private_key'], wrap)
            state['aes_keys'][sender] = aes
        except Exception:
            pass
    aes = state['aes_keys'].get(sender)
    if not aes:
        return {
            'sender': sender,
            'text': '[Older message: unlock with a new message from this contact]',
            'ts': row['timestamp'],
            'server_id': row['id'],
        }
    try:
        text = CryptoUtils.decrypt_aes(aes, enc).decode('utf-8')
        return {'sender': sender, 'text': text, 'ts': row['timestamp'], 'server_id': row['id']}
    except Exception:
        return None


def _merge_history(state, peer, history_rows, username):
    decrypted = []
    for row in history_rows:
        m = _decrypt_history_row(state, username, row)
        if m:
            decrypted.append(m)
    existing = state['messages_by_peer'].setdefault(peer, [])
    by_id = {m['server_id']: m for m in existing if m.get('server_id')}
    for m in decrypted:
        sid = m.get('server_id')
        if sid is not None:
            by_id[sid] = m
    tail = [m for m in existing if not m.get('server_id')]
    sorted_hist = sorted(
        by_id.values(),
        key=lambda x: (str(x.get('ts', '')), x.get('server_id') or 0),
    )
    state['messages_by_peer'][peer] = sorted_hist + tail


def _decrypt_group_row(state, group_id, row, username):
    enc = base64.b64decode(row['encrypted_content_b64'])
    aes = state['group_aes_keys'].get(group_id)
    if not aes:
        return None
    try:
        text = CryptoUtils.decrypt_aes(aes, enc).decode('utf-8')
        sender = row['sender_username']
        return {
            'sender': 'You' if sender == username else sender,
            'text': text,
            'ts': row['timestamp'],
            'server_id': row['id'],
        }
    except Exception:
        return None


def _merge_group_history(state, group_id, history_rows, username):
    decrypted = []
    for row in history_rows:
        m = _decrypt_group_row(state, group_id, row, username)
        if m:
            decrypted.append(m)
    existing = state['messages_by_group'].setdefault(group_id, [])
    by_id = {m['server_id']: m for m in existing if m.get('server_id')}
    for m in decrypted:
        sid = m.get('server_id')
        if sid is not None:
            by_id[sid] = m
    tail = [m for m in existing if not m.get('server_id')]
    sorted_hist = sorted(
        by_id.values(),
        key=lambda x: (str(x.get('ts', '')), x.get('server_id') or 0),
    )
    state['messages_by_group'][group_id] = sorted_hist + tail


def _ingest_groups_tcp(state, groups_payload):
    """TCP `groups` list may include wrapped_key_b64; fills group_aes_keys and groups_list."""
    if not isinstance(groups_payload, list):
        return
    for g in groups_payload:
        gid = g.get('group_id')
        if gid is None:
            continue
        wrap_b64 = g.get('wrapped_key_b64')
        if (
            gid not in state['group_aes_keys']
            and wrap_b64
            and state.get('private_key')
        ):
            try:
                w = base64.b64decode(wrap_b64)
                aes = CryptoUtils.decrypt_rsa(state['private_key'], w)
                state['group_aes_keys'][gid] = aes
            except Exception as e:
                print(f"[Group] decrypt wrap failed gid={gid}: {e}")
    state['groups_list'] = [
        {
            'group_id': x['group_id'],
            'name': x.get('name') or 'Group',
            'members': list(x.get('members') or []),
            'created_by_username': x.get('created_by_username'),
        }
        for x in groups_payload
        if x.get('group_id') is not None
    ]
    tid = state.get('target_group_id')
    cm = state.get('chat_mode') or 'dm'
    if (
        tid is not None
        and cm == 'group'
        and tid in state['group_aes_keys']
        and state['network'].connected
    ):
        state['network'].send_request({'action': 'GET_GROUP_MESSAGES', 'group_id': tid})


def _remove_group_from_state(state, gid):
    state['groups_list'] = [
        g for g in (state.get('groups_list') or []) if g.get('group_id') != gid
    ]
    state['group_aes_keys'].pop(gid, None)
    state['messages_by_group'].pop(gid, None)
    state['unread_groups'].pop(gid, None)
    state['_group_preview'].pop(gid, None)
    if state.get('target_group_id') == gid:
        state['target_group_id'] = None
        state['chat_mode'] = 'dm'
        state['chat_active'] = False


def _register_created_group(state, created):
    if not created or not state.get('private_key'):
        return
    gid = created.get('group_id')
    wrap_b64 = created.get('wrapped_key_b64')
    if gid is None or not wrap_b64:
        return
    try:
        w = base64.b64decode(wrap_b64)
        aes = CryptoUtils.decrypt_rsa(state['private_key'], w)
        state['group_aes_keys'][gid] = aes
    except Exception as e:
        print(f"[Group] created_group decrypt failed: {e}")
    meta = {
        'group_id': gid,
        'name': created.get('name') or 'Group',
        'members': list(created.get('members') or []),
        'created_by_username': state.get('username'),
    }
    gl = state.get('groups_list') or []
    gl = [x for x in gl if x.get('group_id') != gid]
    gl.append(meta)
    state['groups_list'] = sorted(gl, key=lambda x: x['group_id'])
    state['chat_mode'] = 'group'
    state['target_user'] = None
    state['target_group_id'] = gid
    state['unread_groups'].pop(gid, None)
    state['chat_active'] = True
    if state['network'].connected:
        state['network'].send_request({'action': 'GET_GROUP_MESSAGES', 'group_id': gid})


def get_session_state():
    session_id = request.cookies.get('session_id')

    if not session_id or session_id not in sessions:
        session_id = str(uuid.uuid4())
        lock = threading.Lock()
        network = NetworkClient()

        def make_callback(sid):
            def handle_server_message(response):
                if response.get('action') == 'SERVER_READY':
                    return
                if sid in sessions:
                    _handle_server_message_for_session(sid, response)

            return handle_server_message

        sessions[session_id] = {
            'lock': lock,
            'network': network,
            'private_key': None,
            'public_key': None,
            'aes_keys': {},
            'target_pub_keys': {},
            'username': None,
            '_temp_username': None,
            'messages_by_peer': {},
            'last_error': None,
            'last_success': None,
            'last_totp': None,
            '_last_login_username': None,
            'target_user': None,
            'chat_active': False,
            'contacts': set(),
            'all_users': [],
            'online_users': [],
            '_last_send_target': None,
            '_last_preview': {},
            'unread': {},
            'unread_groups': {},
            '_group_preview': {},
            'chat_mode': 'dm',
            'target_group_id': None,
            'messages_by_group': {},
            'group_aes_keys': {},
            'groups_list': [],
            '_last_send_group_id': None,
            'registration_verify': None,
            'user_role': None,
            'display_name': None,
            'permissions': None,
            'admin_users': [],
            '_auth_wait_kind': None,
            '_tcp_wait_event': threading.Event(),
            '_tcp_wait_result': None,
        }
        network.set_receive_callback(make_callback(session_id))
        network.connect(max_rounds=1)
        if not network.connected:
            threading.Thread(target=network.connect, daemon=True).start()
    state = sessions[session_id]
    if '_tcp_wait_event' not in state:
        state['_tcp_wait_event'] = threading.Event()
        state['_tcp_wait_result'] = None
        state['_auth_wait_kind'] = None
    return session_id, state


def _auth_reply_matches_wait(state, response):
    kind = state.get('_auth_wait_kind')
    if not kind:
        return False
    if response.get('verify_flow'):
        return kind == 'verify'
    if kind == 'register':
        return bool(response.get('totp_secret')) or (
            response.get('status') == 'error' and response.get('message')
        )
    if kind == 'login':
        msg = response.get('message') or ''
        return bool(
            response.get('totp_secret')
            or 'Login successful' in msg
            or (response.get('status') == 'error' and msg)
        )
    return False


def _notify_auth_waiter(state, response):
    if not _auth_reply_matches_wait(state, response):
        return
    event = state.get('_tcp_wait_event')
    if event is None:
        return
    with state['lock']:
        if state.get('_tcp_wait_result') is not None:
            return
        state['_tcp_wait_result'] = response
    event.set()


def _begin_auth_wait(state, kind):
    state['_auth_wait_kind'] = kind
    with state['lock']:
        state['_tcp_wait_result'] = None
    event = state.get('_tcp_wait_event')
    if event:
        event.clear()


def _end_auth_wait(state):
    state['_auth_wait_kind'] = None


def _wait_for_auth_reply(state, timeout=10.0):
    event = state.get('_tcp_wait_event')
    if event is None:
        return None
    with state['lock']:
        pending = state.get('_tcp_wait_result')
        if pending is not None:
            state['_tcp_wait_result'] = None
            return pending
    if event.wait(timeout):
        with state['lock']:
            return state.pop('_tcp_wait_result', None)
    with state['lock']:
        return state.pop('_tcp_wait_result', None)
    return None


def _handle_server_message_for_session(session_id, response):
    if session_id not in sessions:
        return
    state = sessions[session_id]
    with state['lock']:
        if response.get('verify_flow'):
            state['registration_verify'] = (
                'success' if response.get('status') == 'success' else 'error'
            )
            if response.get('status') == 'success':
                state['last_totp'] = None
            return

        action = response.get('action')

        if action == 'SERVER_READY':
            return

        if action == 'MSG_DELETED':
            mid = response.get('message_id')
            with_user = response.get('with_user')
            if mid is not None and with_user:
                lst = state['messages_by_peer'].get(with_user, [])
                state['messages_by_peer'][with_user] = [
                    m for m in lst if m.get('server_id') != mid
                ]
                updated = state['messages_by_peer'][with_user]
                for m in reversed(updated):
                    t = m.get('text')
                    if t:
                        _bump_preview(state, with_user, t)
                        break
                else:
                    state['_last_preview'].pop(with_user, None)
            return

        if action == 'GROUP_RENAMED':
            gid = response.get('group_id')
            name = response.get('name')
            if gid is not None and name:
                for g in state.get('groups_list') or []:
                    if g.get('group_id') == gid:
                        g['name'] = name
                        break
            return

        if action == 'GROUP_DELETED':
            gid = response.get('group_id')
            if gid is not None:
                _remove_group_from_state(state, gid)
            return

        if action == 'GROUP_MEMBERS_CHANGED':
            gid = response.get('group_id')
            members = response.get('members')
            if gid is not None and isinstance(members, list):
                for g in state.get('groups_list') or []:
                    if g.get('group_id') == gid:
                        g['members'] = list(members)
                        break
            return

        if action == 'GROUP_MSG_DELETED':
            gid = response.get('group_id')
            mid = response.get('message_id')
            if gid is not None and mid is not None:
                lst = state['messages_by_group'].get(gid, [])
                state['messages_by_group'][gid] = [
                    m for m in lst if m.get('server_id') != mid
                ]
                updated = state['messages_by_group'].get(gid, [])
                for m in reversed(updated or []):
                    t = m.get('text')
                    if t:
                        _bump_group_preview(state, gid, t)
                        break
                else:
                    state['_group_preview'].pop(gid, None)
            return

        if action == 'RECEIVE_GROUP_MSG':
            gid = response.get('group_id')
            sender = response.get('from')
            encrypted_content_b64 = response.get('encrypted_content')
            if gid is None or not sender or not encrypted_content_b64:
                return
            encrypted_content = base64.b64decode(encrypted_content_b64)
            ts = _now_iso()
            preview = '…'
            aes = state['group_aes_keys'].get(gid)
            if aes:
                try:
                    msg = CryptoUtils.decrypt_aes(aes, encrypted_content).decode('utf-8')
                    preview = msg
                    _append_group_message(
                        state,
                        gid,
                        {
                            'sender': sender,
                            'text': msg,
                            'ts': ts,
                            'server_id': None,
                        },
                    )
                except Exception:
                    preview = '<Decryption Failed>'
                    _append_group_message(
                        state,
                        gid,
                        {
                            'sender': sender,
                            'text': '<Decryption Failed>',
                            'ts': ts,
                            'server_id': None,
                        },
                    )
            else:
                preview = '<Encrypted Message - No Key>'
                _append_group_message(
                    state,
                    gid,
                    {
                        'sender': sender,
                        'text': '<Encrypted Message - No Key>',
                        'ts': ts,
                        'server_id': None,
                    },
                )
            _bump_group_preview(state, gid, preview)
            if state.get('chat_mode') != 'group' or state.get('target_group_id') != gid:
                state['unread_groups'][gid] = state['unread_groups'].get(gid, 0) + 1
            return

        if action == 'RECEIVE_MSG':
            sender = response['from']
            encrypted_content_b64 = response['encrypted_content']
            encrypted_content = base64.b64decode(encrypted_content_b64)

            if 'encrypted_aes_key' in response and state['private_key']:
                try:
                    encrypted_aes = base64.b64decode(response['encrypted_aes_key'])
                    aes_key = CryptoUtils.decrypt_rsa(state['private_key'], encrypted_aes)
                    state['aes_keys'][sender] = aes_key
                except Exception as e:
                    print(f"Failed to decrypt AES key from {sender}: {e}")

            ts = _now_iso()
            preview = '…'
            if sender in state['aes_keys']:
                aes_key = state['aes_keys'][sender]
                try:
                    decrypted_bytes = CryptoUtils.decrypt_aes(aes_key, encrypted_content)
                    msg = decrypted_bytes.decode('utf-8')
                    preview = msg
                    _append_peer_message(
                        state,
                        sender,
                        {'sender': sender, 'text': msg, 'ts': ts, 'server_id': None},
                    )
                except Exception:
                    preview = '<Decryption Failed>'
                    _append_peer_message(
                        state,
                        sender,
                        {
                            'sender': sender,
                            'text': '<Decryption Failed>',
                            'ts': ts,
                            'server_id': None,
                        },
                    )
            else:
                preview = '<Encrypted Message - No Key>'
                _append_peer_message(
                    state,
                    sender,
                    {
                        'sender': sender,
                        'text': '<Encrypted Message - No Key>',
                        'ts': ts,
                        'server_id': None,
                    },
                )
            _bump_preview(state, sender, preview)
            if sender != state.get('target_user'):
                state['unread'][sender] = state['unread'].get(sender, 0) + 1
            return

        elif response.get('status') == 'success' and response.get('created_group'):
            _register_created_group(state, response['created_group'])

        elif response.get('status') == 'success' and isinstance(
            response.get('admin_users'), list
        ):
            state['admin_users'] = response['admin_users']

        elif response.get('status') == 'success' and isinstance(
            response.get('groups'), list
        ):
            _ingest_groups_tcp(state, response['groups'])

        elif (
            response.get('status') == 'success'
            and response.get('group_messages') is not None
            and response.get('history_group_id') is not None
        ):
            gid = response['history_group_id']
            if state['username']:
                _merge_group_history(
                    state, gid, response['group_messages'], state['username']
                )
            state['chat_active'] = True

        elif response.get('status') == 'success' and 'public_key' in response:
            if state.get('chat_mode') != 'dm':
                return
            target_user = state['target_user']
            if not target_user:
                return
            pub_key_pem = response['public_key'].encode('utf-8')
            target_pub_key = CryptoUtils.deserialize_public_key(pub_key_pem)

            state['target_pub_keys'][target_user] = target_pub_key

            if target_user not in state['aes_keys']:
                state['aes_keys'][target_user] = CryptoUtils.generate_aes_key()

            state['chat_active'] = True
            state['contacts'].add(target_user)
            peer_msgs = state['messages_by_peer'].setdefault(target_user, [])
            sys_text = f'Secure session established with {target_user}'
            if not peer_msgs or peer_msgs[-1].get('text') != sys_text:
                _append_peer_message(
                    state,
                    target_user,
                    {
                        'sender': 'SYSTEM',
                        'text': sys_text,
                        'ts': _now_iso(),
                        'server_id': None,
                    },
                )
            if state['network'].connected and state['username']:
                state['network'].send_request(
                    {'action': 'GET_MESSAGES', 'target_user': target_user}
                )

        elif (
            response.get('status') == 'success'
            and response.get('messages') is not None
            and response.get('history_peer')
        ):
            peer = response['history_peer']
            if state['username']:
                _merge_history(state, peer, response['messages'], state['username'])

        elif response.get('status') == 'success':
            if response.get('deleted_message_id') is not None:
                peer = response.get('delete_peer')
                mid = response.get('deleted_message_id')
                if peer and mid is not None:
                    lst = state['messages_by_peer'].get(peer, [])
                    state['messages_by_peer'][peer] = [
                        m for m in lst if m.get('server_id') != mid
                    ]
                    updated = state['messages_by_peer'][peer]
                    for m in reversed(updated):
                        t = m.get('text')
                        if t:
                            _bump_preview(state, peer, t)
                            break
                    else:
                        state['_last_preview'].pop(peer, None)

            if response.get('deleted_group_message_id') is not None:
                gid = response.get('group_id')
                mid = response.get('deleted_group_message_id')
                if gid is not None and mid is not None:
                    lst = state['messages_by_group'].get(gid, [])
                    state['messages_by_group'][gid] = [
                        m for m in lst if m.get('server_id') != mid
                    ]
                    updated = state['messages_by_group'].get(gid, [])
                    for m in reversed(updated or []):
                        t = m.get('text')
                        if t:
                            _bump_group_preview(state, gid, t)
                            break
                    else:
                        state['_group_preview'].pop(gid, None)

            if 'all_users' in response:
                state['all_users'] = response['all_users']
                state['online_users'] = response['online_users']

            if response.get('stored_message_id') is not None:
                peer = state.get('_last_send_target')
                if peer:
                    for m in reversed(state['messages_by_peer'].get(peer, [])):
                        if m.get('sender') == 'You' and m.get('server_id') is None:
                            m['server_id'] = response['stored_message_id']
                            break

            if response.get('stored_group_message_id') is not None:
                gid = response.get('group_id')
                if gid is not None:
                    for m in reversed(state['messages_by_group'].get(gid, [])):
                        if m.get('sender') == 'You' and m.get('server_id') is None:
                            m['server_id'] = response['stored_group_message_id']
                            break

            msg = response.get('message', '')
            if 'totp_secret' in response:
                state['last_totp'] = response['totp_secret']
            if msg and msg != 'Message sent' and msg != 'Message deleted':
                if 'Login successful' in msg:
                    state['username'] = state.get('_temp_username')
                    if response.get('role') is not None:
                        state['user_role'] = normalize_role(response['role'])
                    state['permissions'] = response.get('permissions') or permissions_for_role(
                        state.get('user_role')
                    )
                    state['display_name'] = (
                        response.get('display_name')
                        or state.get('username')
                    )
                    state['network'].send_request({'action': 'GET_ALL_USERS'})
                    state['network'].send_request({'action': 'GET_MY_GROUPS'})
                    if state.get('permissions', {}).get('can_admin') or state.get(
                        'permissions', {}
                    ).get('can_moderate'):
                        state['network'].send_request({'action': 'ADMIN_LIST_USERS'})
                if response.get('display_name') and state.get('username'):
                    state['display_name'] = response['display_name']
                if response.get('deleted_group_id') is not None:
                    _remove_group_from_state(state, response['deleted_group_id'])
                if response.get('left_group_id') is not None:
                    _remove_group_from_state(state, response['left_group_id'])
                if response.get('group_id') is not None and response.get('name'):
                    gid = response['group_id']
                    for g in state.get('groups_list') or []:
                        if g.get('group_id') == gid:
                            g['name'] = response['name']
                            break
                state['last_success'] = msg
            _notify_auth_waiter(state, response)

        elif response.get('status') == 'error':
            state['last_error'] = response.get('message', 'Unknown error')
            _notify_auth_waiter(state, response)


def generate_keys_if_needed(state):
    if not state['private_key']:
        state['private_key'], state['public_key'] = CryptoUtils.generate_rsa_key_pair()


@app.route('/')
def index():
    session_id, state = get_session_state()
    response = app.make_response(
        render_template('index.html', csrf_token=session.get('csrf_token', ''))
    )
    response.set_cookie('session_id', session_id)
    return response


@app.route('/api/status', methods=['GET'])
def get_status():
    session_id, state = get_session_state()
    if not state['network'].connected and not state['network'].reconnecting:
        ensure_network(state)
    with state['lock']:
        me = state['username']
        chat_mode = state.get('chat_mode') or 'dm'
        net = state['network']
        all_u = state['all_users'] or []
        on_u = state['online_users'] or []
        if me:
            all_u = [u for u in all_u if u != me]
            on_u = [u for u in on_u if u != me]
        contacts = list(state['contacts'])
        if me:
            contacts = [c for c in contacts if c != me]

        if chat_mode == 'group':
            gid = state.get('target_group_id')
            valid_ids = {g['group_id'] for g in (state.get('groups_list') or [])}
            if me and gid is not None and gid not in valid_ids:
                state['target_group_id'] = None
                state['chat_active'] = False
                state['chat_mode'] = 'dm'
                gid = None
            messages = list(state['messages_by_group'].get(gid) or []) if gid else []
            target_user = None
        else:
            target = state['target_user']
            if me and target == me:
                state['target_user'] = None
                state['chat_active'] = False
                target = None
            messages = list(state['messages_by_peer'].get(target) or [])
            target_user = state['target_user']

        groups_ui = []
        for g in state.get('groups_list') or []:
            gid = g['group_id']
            groups_ui.append(
                {
                    'group_id': gid,
                    'name': g.get('name') or 'Group',
                    'members': g.get('members') or [],
                    'created_by_username': g.get('created_by_username'),
                    'preview': state.get('_group_preview', {}).get(gid, 'Group chat'),
                    'unread': state.get('unread_groups', {}).get(gid, 0),
                }
            )

        tcp_loopback_open = None
        if not net.connected:
            try:
                t = socket.create_connection(('127.0.0.1', net.port), timeout=0.35)
                t.close()
                tcp_loopback_open = True
            except OSError:
                tcp_loopback_open = False

        payload = {
            'connected': net.connected,
            'reconnecting': net.reconnecting,
            'last_network_error': net.last_error_message,
            'tcp_port': net.port,
            'tcp_loopback_open': tcp_loopback_open,
            'username': state['username'],
            'display_name': state.get('display_name') or state['username'],
            'user_role': state.get('user_role'),
            'permissions': state.get('permissions')
            or permissions_for_role(state.get('user_role')),
            'admin_users': list(state.get('admin_users') or []),
            'csrf_token': session.get('csrf_token'),
            'chat_mode': chat_mode,
            'target_user': target_user,
            'target_group_id': state.get('target_group_id'),
            'chat_active': state['chat_active'],
            'messages': messages,
            'error': state['last_error'],
            'success': state['last_success'],
            'totp': state['last_totp'],
            'contacts': contacts,
            'all_users': all_u,
            'online_users': on_u,
            'last_preview': dict(state['_last_preview']),
            'unread': dict(state['unread']),
            'groups': groups_ui,
            'registration_verify': state['registration_verify'],
        }
    response = jsonify(payload)
    response.set_cookie('session_id', session_id)
    return response


@app.route('/api/clear_messages', methods=['POST'])
def clear_msgs():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    with state['lock']:
        state['last_error'] = None
        state['last_success'] = None
        if not data.get('keep_totp'):
            state['last_totp'] = None
        state['registration_verify'] = None
    return jsonify({'status': 'ok'})


@app.route('/api/refresh_users', methods=['POST'])
def refresh_users():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    with state['lock']:
        if state['network'].connected and state['username']:
            state['network'].send_request({'action': 'GET_ALL_USERS'})
            state['network'].send_request({'action': 'GET_MY_GROUPS'})
    return jsonify({'status': 'ok'})


@app.route('/api/connect', methods=['POST'])
def connect():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    ensure_network(state)
    return jsonify({'status': 'connecting'})


@app.route('/api/verify_registration_totp', methods=['POST'])
def verify_registration_totp():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    username = (data.get('username') or '').strip()
    totp_token = (data.get('totp_token') or '').strip()
    if not username or not totp_token:
        return jsonify({'error': 'username and totp_token required'})
    ensure_network(state)
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server. Run: cd server && python3 server.py'})
        state['registration_verify'] = None
        sent = state['network'].send_request(
            {
                'action': 'VERIFY_SETUP_TOTP',
                'username': username,
                'totp_token': totp_token,
            }
        )
    if not sent:
        return jsonify({'error': 'Not connected to server'})
    return jsonify({'status': 'ok'})


@app.route('/api/register', methods=['POST'])
def register():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    ensure_network(state)
    with state['lock']:
        if not state['network'].connected:
            return jsonify(
                {'error': 'Not connected to server. Run: cd server && python3 server.py'}
            )

        generate_keys_if_needed(state)
        pub_key_pem = CryptoUtils.serialize_public_key(state['public_key']).decode('utf-8')

        sent = state['network'].send_request(
            {
                'action': 'REGISTER',
                'username': (username or '').strip(),
                'password': password,
                'public_key': pub_key_pem,
            }
        )
    if not sent:
        return jsonify({'error': 'Not connected to server'})
    return jsonify({'status': 'ok'})


@app.route('/api/login', methods=['POST'])
def login():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json
    username = data.get('username')
    password = data.get('password')
    totp_token = data.get('totp_token')
    ensure_network(state)
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})

        state['_temp_username'] = username
        generate_keys_if_needed(state)
        pub_key_pem = CryptoUtils.serialize_public_key(state['public_key']).decode('utf-8')

        state['network'].send_request(
            {
                'action': 'LOGIN',
                'username': (username or '').strip(),
                'password': password,
                'totp_token': totp_token or '',
                'public_key': pub_key_pem,
            }
        )
    return jsonify({'status': 'ok'})


@app.route('/api/open_group', methods=['POST'])
def open_group():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    try:
        gid = int(data.get('group_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'group_id required'})
    with state['lock']:
        state['chat_mode'] = 'group'
        state['target_user'] = None
        state['target_group_id'] = gid
        state['unread_groups'][gid] = 0
        state['chat_active'] = bool(state['group_aes_keys'].get(gid))
        state['network'].send_request({'action': 'GET_GROUP_MESSAGES', 'group_id': gid})
    return jsonify({'status': 'ok'})


@app.route('/api/create_group', methods=['POST'])
def create_group():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    name = (data.get('name') or 'Group').strip()[:120] or 'Group'
    raw = data.get('members') or data.get('member_usernames') or []
    if isinstance(raw, str):
        raw = [x.strip() for x in raw.replace(',', ' ').split() if x.strip()]
    if not isinstance(raw, list):
        raw = []
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        me = state.get('username')
        if not me:
            return jsonify({'error': 'Not logged in'})
        members = [str(x).strip() for x in raw if str(x).strip()]
        if me not in members:
            members.append(me)
        state['network'].send_request(
            {
                'action': 'CREATE_GROUP',
                'name': name,
                'member_usernames': members,
            }
        )
    return jsonify({'status': 'ok'})


@app.route('/api/start_chat', methods=['POST'])
def start_chat():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({'error': 'Target required'})
    with state['lock']:
        if target == state.get('username'):
            return jsonify({'error': 'Cannot chat with yourself'})
        state['chat_mode'] = 'dm'
        state['target_group_id'] = None
        state['target_user'] = target
        state['unread'][target] = 0
        state['network'].send_request({'action': 'GET_KEY', 'target_user': target})
    return jsonify({'status': 'ok'})


@app.route('/api/send_message', methods=['POST'])
def send_message():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json
    msg = data.get('message')
    with state['lock']:
        if not msg:
            return jsonify({'error': 'Invalid message'})
        chat_mode = state.get('chat_mode') or 'dm'
        if chat_mode == 'group':
            gid = state.get('target_group_id')
            if not gid:
                return jsonify({'error': 'No group selected'})
            gkey = state['group_aes_keys'].get(gid)
            if not gkey:
                return jsonify(
                    {'error': 'Group key not ready — wait for sync or re-open the group.'}
                )
            encrypted_bytes = CryptoUtils.encrypt_aes(gkey, msg.encode('utf-8'))
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
            state['_last_send_group_id'] = gid
            state['network'].send_request(
                {
                    'action': 'SEND_GROUP_MSG',
                    'group_id': gid,
                    'encrypted_content': encrypted_b64,
                }
            )
            ts = _now_iso()
            _append_group_message(
                state,
                gid,
                {'sender': 'You', 'text': msg, 'ts': ts, 'server_id': None},
            )
            _bump_group_preview(state, gid, msg)
            return jsonify({'status': 'ok'})

        if not state['target_user']:
            return jsonify({'error': 'Invalid message'})

        target = state['target_user']
        if target == state.get('username'):
            return jsonify({'error': 'Cannot message yourself'})

        aes_key = state['aes_keys'].get(target)
        target_pub_key = state['target_pub_keys'].get(target)

        if not aes_key or not target_pub_key:
            return jsonify({'error': 'No AES key or Public Key established'})

        encrypted_bytes = CryptoUtils.encrypt_aes(aes_key, msg.encode('utf-8'))
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

        encrypted_aes_key = CryptoUtils.encrypt_rsa(target_pub_key, aes_key)
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')

        state['_last_send_target'] = target
        state['network'].send_request(
            {
                'action': 'SEND_MSG',
                'target_user': target,
                'encrypted_content': encrypted_b64,
                'encrypted_aes_key': encrypted_aes_key_b64,
            }
        )

        ts = _now_iso()
        _append_peer_message(
            state,
            target,
            {'sender': 'You', 'text': msg, 'ts': ts, 'server_id': None},
        )
        _bump_preview(state, target, msg)
    return jsonify({'status': 'ok'})


@app.route('/api/logout', methods=['POST'])
def logout():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    with state['lock']:
        old_net = state['network']
        old_net.close(disable_reconnect=True)

        network = NetworkClient()

        def make_callback(sid):
            def handle_server_message(response):
                if sid in sessions:
                    _handle_server_message_for_session(sid, response)

            return handle_server_message

        network.set_receive_callback(make_callback(session_id))
        state['network'] = network
        state['username'] = None
        state['target_user'] = None
        state['chat_active'] = False
        state['messages_by_peer'] = {}
        state['messages_by_group'] = {}
        state['aes_keys'] = {}
        state['target_pub_keys'] = {}
        state['contacts'] = set()
        state['private_key'] = None
        state['public_key'] = None
        state['all_users'] = []
        state['online_users'] = []
        state['_last_preview'] = {}
        state['_group_preview'] = {}
        state['unread'] = {}
        state['unread_groups'] = {}
        state['_last_send_target'] = None
        state['_last_send_group_id'] = None
        state['user_role'] = None
        state['display_name'] = None
        state['permissions'] = None
        state['admin_users'] = []
        state['chat_mode'] = 'dm'
        state['target_group_id'] = None
        state['group_aes_keys'] = {}
        state['groups_list'] = []

    net = sessions[session_id]['network']
    net.connect(max_rounds=1)
    if not net.connected:
        threading.Thread(target=net.connect, daemon=True).start()
    return jsonify({'status': 'ok'})


@app.route('/api/deselect_chat', methods=['POST'])
def deselect_chat():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    with state['lock']:
        state['target_user'] = None
        state['target_group_id'] = None
        state['chat_mode'] = 'dm'
        state['chat_active'] = False
    return jsonify({'status': 'ok'})


@app.route('/api/delete_message', methods=['POST'])
def delete_message():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    try:
        mid = int(data.get('message_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid message_id'})
    peer = (data.get('peer') or '').strip()
    try:
        gid = data.get('group_id')
        if gid is not None and gid != '':
            gid = int(gid)
        else:
            gid = None
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid group_id'})
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        if gid is not None:
            state['network'].send_request(
                {
                    'action': 'DELETE_GROUP_MESSAGE',
                    'message_id': mid,
                    'group_id': gid,
                }
            )
        else:
            if not peer:
                return jsonify({'error': 'peer required'})
            state['network'].send_request(
                {
                    'action': 'DELETE_MESSAGE',
                    'message_id': mid,
                    'peer_username': peer,
                }
            )
    return jsonify({'status': 'ok'})


@app.route('/api/update_display_name', methods=['POST'])
def update_display_name():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    display_name = (data.get('display_name') or '').strip()
    if not display_name:
        return jsonify({'error': 'Display name is required'})
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        if not state.get('username'):
            return jsonify({'error': 'Not logged in'})
        state['network'].send_request(
            {'action': 'UPDATE_DISPLAY_NAME', 'display_name': display_name[:80]}
        )
    return jsonify({'status': 'ok'})


@app.route('/api/rename_group', methods=['POST'])
def rename_group():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    try:
        gid = int(data.get('group_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'group_id required'})
    name = (data.get('name') or '').strip()[:120]
    if not name:
        return jsonify({'error': 'Group name is required'})
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        if not state.get('username'):
            return jsonify({'error': 'Not logged in'})
        state['network'].send_request(
            {'action': 'RENAME_GROUP', 'group_id': gid, 'name': name}
        )
    return jsonify({'status': 'ok'})


@app.route('/api/delete_group', methods=['POST'])
def delete_group():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    try:
        gid = int(data.get('group_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'group_id required'})
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        if not state.get('username'):
            return jsonify({'error': 'Not logged in'})
        state['network'].send_request({'action': 'DELETE_GROUP', 'group_id': gid})
    return jsonify({'status': 'ok'})


@app.route('/api/leave_group', methods=['POST'])
def leave_group():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    try:
        gid = int(data.get('group_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'group_id required'})
    with state['lock']:
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        if not state.get('username'):
            return jsonify({'error': 'Not logged in'})
        state['network'].send_request({'action': 'LEAVE_GROUP', 'group_id': gid})
    return jsonify({'status': 'ok'})


@app.route('/api/admin/list_users', methods=['POST'])
def admin_list_users():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    with state['lock']:
        perms = state.get('permissions') or {}
        if not perms.get('can_moderate') and not perms.get('can_admin'):
            return jsonify({'error': 'Moderator or admin access required'})
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        state['network'].send_request({'action': 'ADMIN_LIST_USERS'})
    return jsonify({'status': 'ok'})


@app.route('/api/admin/set_role', methods=['POST'])
def admin_set_role():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    username = (data.get('username') or '').strip()
    role = (data.get('role') or '').strip()
    if not username or not role:
        return jsonify({'error': 'username and role required'})
    with state['lock']:
        perms = state.get('permissions') or {}
        if not perms.get('can_admin'):
            return jsonify({'error': 'Master admin access required'})
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        state['network'].send_request(
            {'action': 'ADMIN_SET_ROLE', 'username': username, 'role': role}
        )
        state['network'].send_request({'action': 'ADMIN_LIST_USERS'})
    return jsonify({'status': 'ok'})


@app.route('/api/admin/delete_user', methods=['POST'])
def admin_delete_user():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    data = request.json or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'error': 'username required'})
    with state['lock']:
        perms = state.get('permissions') or {}
        if not perms.get('can_admin'):
            return jsonify({'error': 'Master admin access required'})
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        state['network'].send_request(
            {'action': 'ADMIN_DELETE_USER', 'username': username}
        )
        state['network'].send_request({'action': 'ADMIN_LIST_USERS'})
    return jsonify({'status': 'ok'})


@app.route('/api/rotate_session_keys', methods=['POST'])
def rotate_session_keys():
    bad = _require_csrf()
    if bad is not None:
        return bad
    session_id, state = get_session_state()
    with state['lock']:
        if state.get('chat_mode') != 'dm':
            return jsonify({'error': 'Key rotation applies to direct messages only'})
        target = state['target_user']
        if not target:
            return jsonify({'error': 'Open a conversation first'})
        if not state['network'].connected:
            return jsonify({'error': 'Not connected to server'})
        state['aes_keys'].pop(target, None)
        state['target_pub_keys'].pop(target, None)
        state['chat_active'] = False
        _append_peer_message(
            state,
            target,
            {
                'sender': 'SYSTEM',
                'text': 'Rotating encryption keys for this chat…',
                'ts': _now_iso(),
                'server_id': None,
            },
        )
        state['network'].send_request({'action': 'GET_KEY', 'target_user': target})
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    port = 5001
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    print(f"Starting SecureChat Client on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False, threaded=True)
