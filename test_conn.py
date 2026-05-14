import socket

def test():
    try:
        s = socket.socket()
        s.settimeout(2.0)
        s.connect(('127.0.0.1', 12345))
        print("TCP Connect OK")
        
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp.settimeout(2.0)
        udp.sendto(b'DISCOVER_SERVER', ('<broadcast>', 12346))
        data, addr = udp.recvfrom(1024)
        print("UDP Connect OK:", data, addr)
    except Exception as e:
        print("Error:", e)

test()
