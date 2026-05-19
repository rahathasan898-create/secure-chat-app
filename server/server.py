import socket
import threading
import json
import base64
import sys
import os
import pyotp
from database import Database
from rate_limit import SlidingWindowLimiter
from rbac import (
    MASTER_ADMIN_USERNAME,
    can_manage_users,
    can_moderate_messages,
    normalize_role,
    permissions_for_role,
)

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from shared.crypto import CryptoUtils


def _peer_ip(client_socket):
    try:
        return client_socket.getpeername()[0]
    except Exception:
        return 'unknown'


class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port
        self.db = Database()
        self._login_rate = SlidingWindowLimiter(25, 60.0)
        self._register_rate = SlidingWindowLimiter(8, 3600.0)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        # Map username to client socket for online users
        self.clients = {}

    def _broadcast_group_event(self, group_id, payload):
        for uname in self.db.get_group_member_usernames(group_id):
            sock = self.clients.get(uname)
            if sock:
                try:
                    self.send_response(sock, payload)
                except Exception as ex:
                    print(f"[Server] group broadcast failed: {ex}")

    def _notify_group_deleted(self, member_usernames, group_id):
        note = {'action': 'GROUP_DELETED', 'group_id': group_id}
        for uname in member_usernames:
            sock = self.clients.get(uname)
            if sock:
                try:
                    self.send_response(sock, note)
                except Exception as ex:
                    print(f"[Server] GROUP_DELETED notify: {ex}")

    def start(self):
        print(f"Server listening on {self.host}:{self.port}...")
        threading.Thread(target=self._udp_discovery_listener, daemon=True).start()
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def _udp_discovery_listener(self):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to 0.0.0.0 to listen for broadcasts
        udp_sock.bind(('0.0.0.0', 12346))
        print("UDP Discovery Listener started on port 12346")
        while True:
            try:
                data, addr = udp_sock.recvfrom(1024)
                if data == b'DISCOVER_SERVER':
                    udp_sock.sendto(b'SERVER_HERE', addr)
            except Exception as e:
                print(f"UDP Error: {e}")

    def handle_client(self, client_socket):
        current_user = None
        current_user_id = None
        current_user_role = None
        try:
            # Small handshake so the client can confirm the link before both sides block on app traffic.
            ready = json.dumps(
                {'status': 'ok', 'action': 'SERVER_READY', 'tcp_port': self.port}
            ).encode('utf-8')
            client_socket.sendall(len(ready).to_bytes(4, 'big') + ready)
        except OSError:
            try:
                client_socket.close()
            except OSError:
                pass
            return
        try:
            while True:
                # Read length header (4 bytes)
                raw_length = client_socket.recv(4)
                if not raw_length:
                    break
                msg_length = int.from_bytes(raw_length, 'big')
                
                # Read payload
                payload = b''
                while len(payload) < msg_length:
                    chunk = client_socket.recv(min(4096, msg_length - len(payload)))
                    if not chunk:
                        break
                    payload += chunk
                
                if not payload:
                    break

                request = json.loads(payload.decode('utf-8'))
                action = request.get('action')
                peer_ip = _peer_ip(client_socket)
                print(f"[Server] Received action: {action} from {client_socket.getpeername()}")

                response = {}

                if action == 'REGISTER':
                    if not self._register_rate.allow(peer_ip):
                        print(f"[SECURITY] REGISTER rate limited ip={peer_ip}")
                        response = {
                            'status': 'error',
                            'message': 'Too many registration attempts from this network. Try again later.',
                        }
                        self.send_response(client_socket, response)
                        continue
                    uname = (request.get('username') or '').strip()
                    if (
                        uname.lower() == MASTER_ADMIN_USERNAME
                        and self.db.master_admin_exists()
                    ):
                        response = {
                            'status': 'error',
                            'message': (
                                'A master admin account already exists. '
                                'Sign in or choose a different username.'
                            ),
                        }
                    else:
                        success, totp_secret = self.db.register_user(
                            uname,
                            request['password'],
                            request['public_key'],
                        )
                        if success:
                            response = {
                                'status': 'success',
                                'totp_secret': totp_secret,
                                'message': (
                                    'Registration successful. '
                                    'Set up your authenticator, then sign in.'
                                ),
                            }
                        else:
                            ok, totp_secret = self.db.resume_registration_totp(
                                uname,
                                request['password'],
                                request.get('public_key'),
                            )
                            if ok:
                                response = {
                                    'status': 'success',
                                    'totp_secret': totp_secret,
                                    'message': (
                                        'Finish setting up your authenticator '
                                        'with the code below.'
                                    ),
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': (
                                        'That username is already taken. '
                                        'Sign in, or use the same password here '
                                        'if you still need to finish 2FA setup.'
                                    ),
                                }

                elif action == 'LOGIN':
                    if not self._login_rate.allow(peer_ip):
                        print(f"[SECURITY] LOGIN rate limited ip={peer_ip}")
                        response = {
                            'status': 'error',
                            'message': 'Too many login attempts. Wait a minute and try again.',
                        }
                        self.send_response(client_socket, response)
                        continue
                    auth_res = self.db.authenticate_user(
                        request['username'], request['password']
                    )
                    if auth_res:
                        user_id, totp_secret, role = auth_res
                        role = normalize_role(role)
                        totp_token = (request.get('totp_token') or '').strip()
                        if not totp_secret:
                            response = {
                                'status': 'error',
                                'message': '2FA not configured. Complete registration first.',
                            }
                        elif totp_token and pyotp.TOTP(totp_secret).verify(totp_token):
                            if 'public_key' in request:
                                self.db.update_user_public_key(
                                    request['username'], request['public_key']
                                )
                            current_user = request['username']
                            current_user_id = user_id
                            current_user_role = role
                            if current_user in self.clients:
                                try:
                                    self.clients[current_user].close()
                                except Exception:
                                    pass
                            self.clients[current_user] = client_socket
                            profile = self.db.get_user_profile(user_id)
                            response = {
                                'status': 'success',
                                'message': f'Login successful. Role: {role}',
                                'role': role,
                                'permissions': permissions_for_role(role),
                                'display_name': (
                                    profile['display_name'] if profile else current_user
                                ),
                            }
                        else:
                            response = {
                                'status': 'error',
                                'message': (
                                    'Invalid 6-digit authenticator code. '
                                    'Check your authenticator app and try again.'
                                ),
                            }
                    else:
                        response = {
                            'status': 'error',
                            'message': (
                                'Login failed. Check your username, password, '
                                'and that you have registered.'
                            ),
                        }

                elif action == 'VERIFY_SETUP_TOTP':
                    uname = request.get('username')
                    token = request.get('totp_token')
                    if uname and token and self.db.verify_totp_for_username(uname, token):
                        response = {
                            'status': 'success',
                            'message': 'Authenticator verified',
                            'verify_flow': True,
                        }
                    else:
                        response = {
                            'status': 'error',
                            'message': 'Invalid code or unknown user',
                            'verify_flow': True,
                        }

                elif action == 'GET_KEY':
                    target_user = request.get('target_user')
                    if not target_user:
                        response = {'status': 'error', 'message': 'target_user required'}
                    elif current_user and target_user == current_user:
                        response = {
                            'status': 'error',
                            'message': 'Cannot chat with yourself',
                        }
                    else:
                        pub_key = self.db.get_user_public_key(target_user)
                        if pub_key:
                            response = {'status': 'success', 'public_key': pub_key}
                        else:
                            response = {'status': 'error', 'message': 'User not found'}

                elif action == 'SEND_MSG':
                    if current_user:
                        target_user = request['target_user']
                        if target_user == current_user:
                            response = {
                                'status': 'error',
                                'message': 'Cannot message yourself',
                            }
                        else:
                            encrypted_content = base64.b64decode(request['encrypted_content'])
                            aes_wrapped = None
                            if request.get('encrypted_aes_key'):
                                aes_wrapped = base64.b64decode(request['encrypted_aes_key'])
                            stored_id = self.db.store_message(
                                current_user_id, target_user, encrypted_content, aes_wrapped
                            )
                            if stored_id is not None:
                                # Forward message if user is online
                                if target_user in self.clients:
                                    target_socket = self.clients[target_user]
                                    fwd_msg = {
                                        'action': 'RECEIVE_MSG',
                                        'from': current_user,
                                        'encrypted_content': request['encrypted_content']
                                    }
                                    if 'encrypted_aes_key' in request:
                                        fwd_msg['encrypted_aes_key'] = request['encrypted_aes_key']
                                    self.send_response(target_socket, fwd_msg)
                                response = {
                                    'status': 'success',
                                    'message': 'Message sent',
                                    'stored_message_id': stored_id,
                                }
                            else:
                                response = {'status': 'error', 'message': 'Failed to send'}
                    else:
                        response = {'status': 'error', 'message': 'Not logged in'}

                elif action == 'GET_ALL_USERS':
                    all_users = self.db.get_all_users()
                    online_users = list(self.clients.keys())
                    response = {
                        'status': 'success',
                        'all_users': all_users,
                        'online_users': online_users
                    }

                elif action == 'GET_MY_GROUPS':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        rows = self.db.list_groups_for_user(current_user_id)
                        groups = []
                        for row in rows:
                            groups.append(
                                {
                                    'group_id': row['group_id'],
                                    'name': row['name'],
                                    'members': row['members'],
                                    'created_by_username': row.get('created_by_username'),
                                    'wrapped_key_b64': base64.b64encode(
                                        row['wrapped_key']
                                    ).decode('ascii'),
                                }
                            )
                        response = {'status': 'success', 'groups': groups}

                elif action == 'UPDATE_DISPLAY_NAME':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        new_name = request.get('display_name', '')
                        if self.db.update_display_name(current_user_id, new_name):
                            profile = self.db.get_user_profile(current_user_id)
                            response = {
                                'status': 'success',
                                'message': 'Display name updated',
                                'display_name': profile['display_name'],
                            }
                        else:
                            response = {
                                'status': 'error',
                                'message': 'Invalid display name',
                            }

                elif action == 'RENAME_GROUP':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        try:
                            gid = int(request.get('group_id'))
                        except (TypeError, ValueError):
                            gid = None
                        new_name = request.get('name', '')
                        if gid is None:
                            response = {'status': 'error', 'message': 'group_id required'}
                        elif not self.db.is_group_member(gid, current_user_id):
                            response = {'status': 'error', 'message': 'Not a member'}
                        elif self.db.rename_group(gid, current_user_id, new_name):
                            name = (new_name or '').strip()[:120] or 'Group'
                            self._broadcast_group_event(
                                gid,
                                {
                                    'action': 'GROUP_RENAMED',
                                    'group_id': gid,
                                    'name': name,
                                },
                            )
                            response = {
                                'status': 'success',
                                'message': 'Group renamed',
                                'group_id': gid,
                                'name': name,
                            }
                        else:
                            response = {
                                'status': 'error',
                                'message': 'Only the group creator can rename',
                            }

                elif action == 'DELETE_GROUP':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        try:
                            gid = int(request.get('group_id'))
                        except (TypeError, ValueError):
                            gid = None
                        if gid is None:
                            response = {'status': 'error', 'message': 'group_id required'}
                        elif not self.db.is_group_member(gid, current_user_id):
                            response = {'status': 'error', 'message': 'Not a member'}
                        else:
                            members = self.db.get_group_member_usernames(gid)
                            if self.db.delete_group(gid, current_user_id):
                                self._notify_group_deleted(members, gid)
                                response = {
                                    'status': 'success',
                                    'message': 'Group deleted',
                                    'deleted_group_id': gid,
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': 'Only the group creator can delete',
                                }

                elif action == 'LEAVE_GROUP':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        try:
                            gid = int(request.get('group_id'))
                        except (TypeError, ValueError):
                            gid = None
                        if gid is None:
                            response = {'status': 'error', 'message': 'group_id required'}
                        elif not self.db.is_group_member(gid, current_user_id):
                            response = {'status': 'error', 'message': 'Not a member'}
                        else:
                            members_before = self.db.get_group_member_usernames(gid)
                            if self.db.leave_group(gid, current_user_id):
                                still = self.db.get_group_member_usernames(gid)
                                if still:
                                    self._broadcast_group_event(
                                        gid,
                                        {
                                            'action': 'GROUP_MEMBERS_CHANGED',
                                            'group_id': gid,
                                            'members': still,
                                            'left_user': current_user,
                                        },
                                    )
                                else:
                                    self._notify_group_deleted(members_before, gid)
                                response = {
                                    'status': 'success',
                                    'message': 'Left group',
                                    'left_group_id': gid,
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': 'Could not leave group',
                                }

                elif action == 'CREATE_GROUP':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        name = (request.get('name') or 'Group').strip()[:120] or 'Group'
                        raw_members = request.get('member_usernames') or []
                        if isinstance(raw_members, str):
                            raw_members = [
                                x.strip()
                                for x in raw_members.replace(',', ' ').split()
                                if x.strip()
                            ]
                        member_set = set(raw_members)
                        member_set.add(current_user)
                        if len(member_set) < 2:
                            response = {
                                'status': 'error',
                                'message': 'Add at least one other person to the group',
                            }
                        else:
                            resolved = self.db.resolve_usernames_to_ids(member_set)
                            if len(resolved) != len(member_set):
                                response = {
                                    'status': 'error',
                                    'message': 'One or more usernames are unknown',
                                }
                            else:
                                missing_pk = []
                                wraps = {}
                                group_aes = CryptoUtils.generate_aes_key()
                                for uname, uid in resolved.items():
                                    pem = self.db.get_user_public_key(uname)
                                    if not pem:
                                        missing_pk.append(uname)
                                        break
                                    try:
                                        pk = CryptoUtils.deserialize_public_key(
                                            pem.encode('utf-8')
                                        )
                                        wraps[uid] = CryptoUtils.encrypt_rsa(pk, group_aes)
                                    except Exception as ex:
                                        print(f"[CREATE_GROUP] wrap failed: {ex}")
                                        missing_pk.append(uname)
                                        break
                                if missing_pk:
                                    response = {
                                        'status': 'error',
                                        'message': (
                                            'Missing RSA public key for: '
                                            + ', '.join(missing_pk)
                                            + '. Each member must log in once so their key is registered.'
                                        ),
                                    }
                                else:
                                    gid = self.db.create_group(
                                        name, current_user_id, wraps
                                    )
                                    if gid:
                                        member_names_sorted = sorted(resolved.keys())
                                        my_wrap = wraps[current_user_id]
                                        response = {
                                            'status': 'success',
                                            'message': 'Group created',
                                            'created_group': {
                                                'group_id': gid,
                                                'name': name,
                                                'members': member_names_sorted,
                                                'wrapped_key_b64': base64.b64encode(
                                                    my_wrap
                                                ).decode('ascii'),
                                            },
                                        }
                                    else:
                                        response = {
                                            'status': 'error',
                                            'message': 'Could not create group',
                                        }

                elif action == 'GET_GROUP_MESSAGES':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        try:
                            gid = int(request.get('group_id'))
                        except (TypeError, ValueError):
                            gid = None
                        if gid is None:
                            response = {
                                'status': 'error',
                                'message': 'group_id required',
                            }
                        elif not self.db.is_group_member(gid, current_user_id):
                            response = {
                                'status': 'error',
                                'message': 'Not a group member',
                            }
                        else:
                            rows = self.db.get_group_messages(gid)
                            out = []
                            for r in rows:
                                out.append(
                                    {
                                        'id': r['id'],
                                        'timestamp': r['timestamp'],
                                        'sender_username': r['sender_username'],
                                        'encrypted_content_b64': base64.b64encode(
                                            r['encrypted_content']
                                        ).decode('ascii'),
                                    }
                                )
                            response = {
                                'status': 'success',
                                'group_messages': out,
                                'history_group_id': gid,
                            }

                elif action == 'SEND_GROUP_MSG':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        try:
                            gid = int(request.get('group_id'))
                        except (TypeError, ValueError):
                            gid = None
                        enc_b64 = request.get('encrypted_content')
                        if gid is None or not enc_b64:
                            response = {
                                'status': 'error',
                                'message': 'group_id and encrypted_content required',
                            }
                        elif not self.db.is_group_member(gid, current_user_id):
                            response = {
                                'status': 'error',
                                'message': 'Not a group member',
                            }
                        else:
                            ciphertext = base64.b64decode(enc_b64)
                            mid = self.db.insert_group_message(
                                gid, current_user_id, ciphertext
                            )
                            if mid:
                                fwd = {
                                    'action': 'RECEIVE_GROUP_MSG',
                                    'group_id': gid,
                                    'from': current_user,
                                    'encrypted_content': enc_b64,
                                }
                                for uname in self.db.get_group_member_usernames(gid):
                                    if uname == current_user:
                                        continue
                                    if uname in self.clients:
                                        try:
                                            self.send_response(
                                                self.clients[uname], fwd
                                            )
                                        except Exception as ex:
                                            print(
                                                f"[Server] group forward failed: {ex}"
                                            )
                                response = {
                                    'status': 'success',
                                    'message': 'Message sent',
                                    'stored_group_message_id': mid,
                                    'group_id': gid,
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': 'Failed to store',
                                }

                elif action == 'DELETE_GROUP_MESSAGE':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        try:
                            mid = int(request.get('message_id'))
                            gid = int(request.get('group_id'))
                        except (TypeError, ValueError):
                            mid = None
                            gid = None
                        if mid is None or gid is None:
                            response = {
                                'status': 'error',
                                'message': 'message_id and group_id required',
                            }
                        else:
                            row = self.db.get_group_message_row(mid)
                            if not row or row['group_id'] != gid:
                                response = {
                                    'status': 'error',
                                    'message': 'Message not found',
                                }
                            elif not self.db.is_group_member(
                                gid, current_user_id
                            ) and not can_moderate_messages(current_user_role):
                                response = {
                                    'status': 'error',
                                    'message': 'Not permitted',
                                }
                            elif can_moderate_messages(
                                current_user_role
                            ) and not self.db.is_group_member(gid, current_user_id):
                                if self.db.delete_group_message_by_id(mid):
                                    note = {
                                        'action': 'GROUP_MSG_DELETED',
                                        'group_id': gid,
                                        'message_id': mid,
                                        'by_user': current_user,
                                    }
                                    for uname in self.db.get_group_member_usernames(gid):
                                        if uname in self.clients:
                                            try:
                                                self.send_response(
                                                    self.clients[uname], note
                                                )
                                            except Exception as ex:
                                                print(
                                                    f"[Server] GROUP_MSG_DELETED mod: {ex}"
                                                )
                                    response = {
                                        'status': 'success',
                                        'message': 'Message deleted (moderation)',
                                        'deleted_group_message_id': mid,
                                        'group_id': gid,
                                    }
                                else:
                                    response = {
                                        'status': 'error',
                                        'message': 'Delete failed',
                                    }
                            elif self.db.delete_group_message_if_sender(
                                mid, current_user_id
                            ):
                                note = {
                                    'action': 'GROUP_MSG_DELETED',
                                    'group_id': gid,
                                    'message_id': mid,
                                    'by_user': current_user,
                                }
                                for uname in self.db.get_group_member_usernames(gid):
                                    if uname in self.clients:
                                        try:
                                            self.send_response(
                                                self.clients[uname], note
                                            )
                                        except Exception as ex:
                                            print(
                                                f"[Server] GROUP_MSG_DELETED notify: {ex}"
                                            )
                                response = {
                                    'status': 'success',
                                    'message': 'Message deleted',
                                    'deleted_group_message_id': mid,
                                    'group_id': gid,
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': 'Only the sender can delete this message',
                                }

                elif action == 'ADMIN_LIST_USERS':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    elif not can_moderate_messages(current_user_role):
                        response = {'status': 'error', 'message': 'Admin access required'}
                    else:
                        online = set(self.clients.keys())
                        users = self.db.list_users_admin()
                        for u in users:
                            u['online'] = u['username'] in online
                        response = {
                            'status': 'success',
                            'admin_users': users,
                        }

                elif action == 'ADMIN_SET_ROLE':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    elif not can_manage_users(current_user_role):
                        response = {
                            'status': 'error',
                            'message': 'Master admin access required',
                        }
                    else:
                        target = (request.get('username') or '').strip()
                        new_role = request.get('role', '')
                        ok, err = self.db.set_user_role(
                            current_user_id, target, new_role
                        )
                        if ok:
                            response = {
                                'status': 'success',
                                'message': f'Role updated for {target}',
                            }
                        else:
                            response = {'status': 'error', 'message': err or 'Failed'}

                elif action == 'ADMIN_DELETE_USER':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    elif not can_manage_users(current_user_role):
                        response = {
                            'status': 'error',
                            'message': 'Master admin access required',
                        }
                    else:
                        target = (request.get('username') or '').strip()
                        ok, err = self.db.delete_user_admin(
                            current_user_id, target
                        )
                        if ok:
                            if target in self.clients:
                                try:
                                    self.clients[target].close()
                                except Exception:
                                    pass
                                self.clients.pop(target, None)
                            response = {
                                'status': 'success',
                                'message': f'User {target} deleted',
                            }
                        else:
                            response = {'status': 'error', 'message': err or 'Failed'}

                elif action == 'GET_MESSAGES':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        peer = request.get('target_user')
                        if not peer:
                            response = {'status': 'error', 'message': 'target_user required'}
                        elif peer == current_user:
                            response = {
                                'status': 'error',
                                'message': 'Invalid peer for history',
                            }
                        else:
                            rows = self.db.get_messages_for_thread(current_user_id, peer)
                            out = []
                            for r in rows:
                                item = {
                                    'id': r['id'],
                                    'timestamp': r['timestamp'],
                                    'sender_username': r['sender_username'],
                                    'receiver_username': r['receiver_username'],
                                    'encrypted_content_b64': base64.b64encode(
                                        r['encrypted_content']
                                    ).decode('utf-8'),
                                }
                                raw_aes = r.get('encrypted_aes_key_receiver')
                                if raw_aes:
                                    item['encrypted_aes_key_b64'] = base64.b64encode(
                                        raw_aes
                                    ).decode('utf-8')
                                out.append(item)
                            response = {
                                'status': 'success',
                                'messages': out,
                                'history_peer': peer,
                            }

                elif action == 'DELETE_MESSAGE':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        peer = request.get('peer_username')
                        raw_id = request.get('message_id')
                        try:
                            mid = int(raw_id)
                        except (TypeError, ValueError):
                            mid = None
                        if not peer or mid is None:
                            response = {
                                'status': 'error',
                                'message': 'message_id and peer_username required',
                            }
                        else:
                            parts = self.db.get_message_participants(mid)
                            if not parts:
                                response = {
                                    'status': 'error',
                                    'message': 'Message not found',
                                }
                            elif current_user not in parts and not can_moderate_messages(
                                current_user_role
                            ):
                                response = {
                                    'status': 'error',
                                    'message': 'Message not found or not permitted',
                                }
                            elif can_moderate_messages(current_user_role) and current_user not in parts:
                                deleted = self.db.delete_message_by_id(mid)
                                if deleted:
                                    sender_n, recv_n = parts
                                    for uname in (sender_n, recv_n):
                                        if uname in self.clients:
                                            try:
                                                self.send_response(
                                                    self.clients[uname],
                                                    {
                                                        'action': 'MSG_DELETED',
                                                        'message_id': mid,
                                                        'with_user': current_user,
                                                    },
                                                )
                                            except Exception as ex:
                                                print(f"[Server] MSG_DELETED mod: {ex}")
                                    print(
                                        f"[SECURITY] moderator_deleted id={mid} by={current_user}"
                                    )
                                    response = {
                                        'status': 'success',
                                        'message': 'Message deleted (moderation)',
                                        'deleted_message_id': mid,
                                        'delete_peer': peer,
                                    }
                                else:
                                    response = {
                                        'status': 'error',
                                        'message': 'Delete failed',
                                    }
                            elif self.db.delete_message_if_participant(
                                mid, current_user_id
                            ):
                                print(
                                    f"[SECURITY] message_deleted id={mid} user={current_user} ip={peer_ip}"
                                )
                                sender_n, recv_n = parts
                                other = (
                                    recv_n if current_user == sender_n else sender_n
                                )
                                if other in self.clients:
                                    try:
                                        self.send_response(
                                            self.clients[other],
                                            {
                                                'action': 'MSG_DELETED',
                                                'message_id': mid,
                                                'with_user': current_user,
                                            },
                                        )
                                    except Exception as ex:
                                        print(
                                            f"[Server] MSG_DELETED notify failed: {ex}"
                                        )
                                response = {
                                    'status': 'success',
                                    'message': 'Message deleted',
                                    'deleted_message_id': mid,
                                    'delete_peer': peer,
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': 'Message not found or not permitted',
                                }

                # Send response back to the client
                self.send_response(client_socket, response)

        except Exception as e:
            print(f"Error handling client {current_user}: {e}")
        finally:
            if current_user and current_user in self.clients:
                del self.clients[current_user]
            client_socket.close()

    def send_response(self, client_socket, response):
        try:
            print(f"[Server] Sending response: {response.get('action', response.get('status'))} to {client_socket.getpeername()}")
            payload = json.dumps(response).encode('utf-8')
            client_socket.sendall(len(payload).to_bytes(4, 'big') + payload)
        except Exception as e:
            print(f"[Server] Send Error: {e}")

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
