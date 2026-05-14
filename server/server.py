import socket
import threading
import json
import base64
import pyotp
from database import Database

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port
        self.db = Database()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        # Map username to client socket for online users
        self.clients = {}
        print(f"Server listening on {self.host}:{self.port}...")

    def start(self):
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
                print(f"[Server] Received action: {action} from {client_socket.getpeername()}")

                response = {}

                if action == 'REGISTER':
                    success, totp_secret = self.db.register_user(
                        request['username'], 
                        request['password'], 
                        request['public_key']
                    )
                    if success:
                        response = {
                            'status': 'success', 
                            'totp_secret': totp_secret, 
                            'message': f'Registration successful. Your 2FA Secret is: {totp_secret}\nSave this or add to Google Authenticator!'
                        }
                    else:
                        response = {'status': 'error', 'message': 'That username is already taken! Please choose another one.'}

                elif action == 'LOGIN':
                    auth_res = self.db.authenticate_user(request['username'], request['password'])
                    if auth_res:
                        user_id, totp_secret, role = auth_res
                        totp_token = request.get('totp_token')
                        
                        totp = pyotp.TOTP(totp_secret)
                        if totp.verify(totp_token):
                            if 'public_key' in request:
                                self.db.update_user_public_key(request['username'], request['public_key'])
                            current_user = request['username']
                            current_user_id = user_id
                            self.clients[current_user] = client_socket
                            response = {'status': 'success', 'message': f'Login successful. Role: {role}'}
                        else:
                            response = {'status': 'error', 'message': 'Invalid 6-digit 2FA token. Please check your authenticator code!'}
                    else:
                        response = {'status': 'error', 'message': "Login Failed. Please make sure you have Registered first, or check your password!"}

                elif action == 'GET_KEY':
                    pub_key = self.db.get_user_public_key(request['target_user'])
                    if pub_key:
                        response = {'status': 'success', 'public_key': pub_key}
                    else:
                        response = {'status': 'error', 'message': 'User not found'}

                elif action == 'SEND_MSG':
                    if current_user:
                        target_user = request['target_user']
                        encrypted_content = base64.b64decode(request['encrypted_content'])
                        
                        # Store in DB
                        success = self.db.store_message(current_user_id, target_user, encrypted_content)
                        if success:
                            # Forward message if user is online
                            if target_user in self.clients:
                                target_socket = self.clients[target_user]
                                fwd_msg = {
                                    'action': 'RECEIVE_MSG',
                                    'from': current_user,
                                    'encrypted_content': request['encrypted_content']
                                }
                                self.send_response(target_socket, fwd_msg)
                            response = {'status': 'success', 'message': 'Message sent'}
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
