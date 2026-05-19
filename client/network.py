import socket
import threading
import json
import time
import os

_DEFAULT_TCP_PORT = 12345
_CONNECT_ROUNDS = 3
_ROUND_PAUSE_SEC = 0.45


def _tcp_port_from_env():
    try:
        return int(os.environ.get('SECURECHAT_TCP_PORT', str(_DEFAULT_TCP_PORT)))
    except ValueError:
        return _DEFAULT_TCP_PORT


def _guess_primary_ipv4():
    """
    Best-effort primary LAN IPv4 of this machine (same host as Flask).
    Helps when UDP broadcast fails but the TCP server listens on 0.0.0.0.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('192.0.2.1', 80))  # TEST-NET-1, no traffic sent
            ip = s.getsockname()[0]
            if ip and not ip.startswith('127.'):
                return ip
        finally:
            s.close()
    except OSError:
        pass
    return None


class NetworkClient:
    """
    TCP client to SecureChat server.

    Connection strategy (no env required for typical dev):
      - **UDP discovery** runs in a **background thread** so it does not delay **127.0.0.1**.
      - Tries **127.0.0.1** first (short timeout), then this machine's **LAN IPv4** (same host,
        different interface), then the **discovered** address.
      - Repeats up to **3 rounds** with short pauses if ``server.py`` starts after the web app.

    Override with ``SECURECHAT_TCP_HOST`` / ``SECURECHAT_TCP_PORT`` if needed.
    ``SECURECHAT_SKIP_DISCOVERY=1`` disables UDP (faster on broken broadcast).
    """

    def __init__(self, host='127.0.0.1', port=None):
        self.host = host
        self.port = port if port is not None else _tcp_port_from_env()
        self.socket = None
        self.receive_callback = None
        self.connected = False
        self._listen_thread = None
        self._reconnect_thread = None
        self._reconnect_lock = threading.Lock()
        self._allow_reconnect = True
        self.last_error_message = None

    @property
    def reconnecting(self):
        t = self._reconnect_thread
        return bool(t and t.is_alive() and not self.connected)

    def discover_server(self, timeout=2.5):
        """Broadcasts UDP to find server IP. Returns IP or None."""
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            udp_sock.bind(('0.0.0.0', 0))
        except OSError:
            pass
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

    def _attempt_tcp(self, host, timeout_sec):
        """Returns a connected socket or None."""
        if not host:
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_sec)
        try:
            s.connect((host, self.port))
            s.settimeout(None)
            return s
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            return None

    def _adopt_socket(self, sock, host):
        self.host = host
        self.socket = sock
        self.connected = True
        self.last_error_message = None
        print(f'[Network] Connected to {host}:{self.port}')
        self._listen_thread = threading.Thread(target=self._listen, daemon=True)
        self._listen_thread.start()

    def _ordered_candidates(self, discovered_ip, lan_ip):
        """Single pass: env → loopback → LAN self → UDP result (deduped)."""
        out = []
        seen = set()

        def add(h):
            if not h or h in seen:
                return
            seen.add(h)
            out.append(h)

        env_host = os.environ.get('SECURECHAT_TCP_HOST', '').strip()
        if env_host:
            add(env_host)
        add('127.0.0.1')
        if lan_ip:
            add(lan_ip)
        if discovered_ip:
            add(discovered_ip)
        return out

    def _tcp_connect_once(self, discovered_holder, lan_ip):
        """One pass over candidates; uses discovery result when available."""
        discovered_ip = discovered_holder[0]
        last_err = None
        for host in self._ordered_candidates(discovered_ip, lan_ip):
            is_loopback = host == '127.0.0.1'
            timeout = 0.85 if is_loopback else 2.2
            print(f'[Network] Trying TCP {host}:{self.port} (timeout {timeout}s) …')
            sock = self._attempt_tcp(host, timeout)
            if sock is not None:
                self._adopt_socket(sock, host)
                return None
            last_err = OSError(f'{host}:{self.port} unreachable')
            print(f'[Network] Failed {host}:{self.port}')
        return last_err

    def _tcp_connect(self, max_rounds=_CONNECT_ROUNDS):
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

        skip_udp = os.environ.get('SECURECHAT_SKIP_DISCOVERY', '').lower() in (
            '1',
            'true',
            'yes',
        )
        lan_ip = _guess_primary_ipv4()

        last_err = None
        for round_i in range(max_rounds):
            discovered_holder = [None]
            disco_thread = None

            if not skip_udp:
                def discover_job(holder=discovered_holder):
                    try:
                        holder[0] = self.discover_server(timeout=2.4)
                    except Exception:
                        holder[0] = None

                disco_thread = threading.Thread(target=discover_job, daemon=True)
                disco_thread.start()
                # Let discovery and first localhost attempt overlap
                time.sleep(0.08)

            # Try with whatever we have; join discovery briefly between attempts
            for sub_try in range(3):
                if disco_thread is not None:
                    disco_thread.join(timeout=0.35)
                err = self._tcp_connect_once(discovered_holder, lan_ip)
                if self.connected:
                    if disco_thread is not None:
                        disco_thread.join(timeout=0.1)
                    return
                last_err = err or last_err
                if skip_udp or (disco_thread is not None and not disco_thread.is_alive()):
                    break
                time.sleep(0.12)

            if disco_thread is not None:
                disco_thread.join(timeout=0.5)

            err = self._tcp_connect_once(discovered_holder, lan_ip)
            if self.connected:
                return
            last_err = err or last_err

            if round_i + 1 < max_rounds:
                pause = _ROUND_PAUSE_SEC * (round_i + 1)
                print(
                    f'[Network] Round {round_i + 1}/{max_rounds} failed; '
                    f'retry in {pause:.2f}s…'
                )
                time.sleep(pause)

        if last_err is not None:
            raise last_err
        raise ConnectionError('Could not connect to SecureChat TCP server')

    def connect(self, max_rounds=_CONNECT_ROUNDS):
        if self.connected:
            return True
        try:
            self._tcp_connect(max_rounds=max_rounds)
            return True
        except Exception as e:
            self.last_error_message = str(e)
            print(f'Connection error: {e}')
            self.connected = False
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
            self._start_reconnect_worker()
            return False

    def _start_reconnect_worker(self):
        if not self._allow_reconnect:
            return
        with self._reconnect_lock:
            if self.connected:
                return
            if self._reconnect_thread and self._reconnect_thread.is_alive():
                return

            def worker():
                delay = 1.0
                max_delay = 30.0
                while self._allow_reconnect and not self.connected:
                    try:
                        self._tcp_connect()
                        return
                    except Exception as e:
                        self.last_error_message = str(e)
                        print(f'Reconnect attempt failed: {e}')
                    time.sleep(delay)
                    delay = min(delay * 2.0, max_delay)

            self._reconnect_thread = threading.Thread(target=worker, daemon=True)
            self._reconnect_thread.start()

    def set_receive_callback(self, callback):
        self.receive_callback = callback

    def _listen(self):
        try:
            while self.connected:
                raw_length = self.socket.recv(4)
                if not raw_length:
                    break
                msg_length = int.from_bytes(raw_length, 'big')

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
            print(f'Listen error: {e}')
            self.last_error_message = str(e)
        finally:
            self.connected = False
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
            if self._allow_reconnect:
                self._start_reconnect_worker()

    def send_request(self, data):
        if not self.connected:
            return False
        try:
            payload = json.dumps(data).encode('utf-8')
            self.socket.sendall(len(payload).to_bytes(4, 'big') + payload)
            return True
        except Exception as e:
            print(f'Send error: {e}')
            self.last_error_message = str(e)
            self.connected = False
            try:
                if self.socket:
                    self.socket.close()
            except Exception:
                pass
            self.socket = None
            if self._allow_reconnect:
                self._start_reconnect_worker()
            return False

    def close(self, disable_reconnect=True):
        if disable_reconnect:
            self._allow_reconnect = False
        self.connected = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
