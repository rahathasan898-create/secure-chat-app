import socket
import threading
import json

class NetworkClient:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.receive_callback = None
        self.connected = False

    def discover_server(self, timeout=3.0):
        """Broadcasts UDP to find server IP. Returns IP or None."""
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.settimeout(timeout)
        
        try:
            udp_sock.sendto(b'DISCOVER_SERVER', ('<broadcast>', 12346))
            while True:
                data, addr = udp_sock.recvfrom(1024)
                if data == b'SERVER_HERE':
                    return addr[0]
        except socket.timeout:
            return None
        finally:
            udp_sock.close()

    def connect(self):
        if self.connected:
            return True
            
        try:
            # Try to discover server
            discovered_ip = self.discover_server()
            if discovered_ip:
                self.host = discovered_ip
                print(f"Auto-discovered server at {self.host}")
            else:
                print(f"Discovery timeout, defaulting to {self.host}")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # Start background thread to listen for incoming messages
            threading.Thread(target=self._listen, daemon=True).start()
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def set_receive_callback(self, callback):
        self.receive_callback = callback

    def _listen(self):
        while self.connected:
            try:
                # Read length header
                raw_length = self.socket.recv(4)
                if not raw_length:
                    break
                msg_length = int.from_bytes(raw_length, 'big')
                
                # Read payload
                payload = b''
                while len(payload) < msg_length:
                    chunk = self.socket.recv(min(4096, msg_length - len(payload)))
                    if not chunk:
                        break
                    payload += chunk
                
                if payload and self.receive_callback:
                    response = json.loads(payload.decode('utf-8'))
                    self.receive_callback(response)
                    
            except Exception as e:
                print(f"Listen error: {e}")
                self.connected = False
                break

    def send_request(self, data):
        if not self.connected:
            return False
        try:
            payload = json.dumps(data).encode('utf-8')
            self.socket.sendall(len(payload).to_bytes(4, 'big') + payload)
            return True
        except Exception as e:
            print(f"Send error: {e}")
            self.connected = False
            return False

    def close(self):
        self.connected = False
        if self.socket:
            self.socket.close()
