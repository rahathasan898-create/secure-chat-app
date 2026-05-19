import socket
import json
import pyotp
import time
import sys

def recv_msg(sock):
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    msg_length = int.from_bytes(raw_length, 'big')
    payload = b''
    while len(payload) < msg_length:
        chunk = sock.recv(msg_length - len(payload))
        if not chunk:
            break
        payload += chunk
    return json.loads(payload.decode('utf-8'))


def recv_msg_optional(sock, timeout_sec=1.0):
    prev = sock.gettimeout()
    sock.settimeout(timeout_sec)
    try:
        return recv_msg(sock)
    except (socket.timeout, json.JSONDecodeError, OSError):
        return None
    finally:
        sock.settimeout(prev)


def send_msg(sock, data):
    payload = json.dumps(data).encode('utf-8')
    sock.sendall(len(payload).to_bytes(4, 'big') + payload)

def test_flow():
    print("Connecting to server...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(('127.0.0.1', 12345))
    except Exception as e:
        print(f"FAILED TO CONNECT: {e}")
        return

    first = recv_msg_optional(s, 1.0)
    if first:
        print(f"First frame from server: {first}")

    username = f"testuser_{int(time.time())}"
    
    # 1. REGISTER
    print(f"Registering {username}...")
    send_msg(s, {
        'action': 'REGISTER',
        'username': username,
        'password': 'Password123!',
        'public_key': 'dummy_pub_key'
    })
    
    resp = recv_msg(s)
    print(f"Register Response: {resp}")
    if resp.get('status') != 'success':
        print("REGISTRATION FAILED")
        return
        
    totp_secret = resp.get('totp_secret')
    if not totp_secret:
        print("NO 2FA SECRET RETURNED")
        return
        
    print("Registration successful. Generating 2FA code...")
    totp = pyotp.TOTP(totp_secret)
    code = totp.now()
    
    # 2. LOGIN
    print(f"Logging in with code {code}...")
    send_msg(s, {
        'action': 'LOGIN',
        'username': username,
        'password': 'Password123!',
        'totp_token': code
    })
    
    resp = recv_msg(s)
    print(f"Login Response: {resp}")
    if resp.get('status') != 'success':
        print("LOGIN FAILED")
        return

    send_msg(s, {'action': 'GET_ALL_USERS'})
    resp2 = recv_msg(s)
    print(f"GET_ALL_USERS Response: {resp2}")
    if resp2.get('status') != 'success' or 'all_users' not in resp2:
        print("GET_ALL_USERS FAILED")
        return
    if username not in resp2['all_users']:
        print("USERNAME NOT IN ROSTER")
        return

    print("ALL TESTS PASSED: E2E Flow Working Properly!")

test_flow()
