from client.network import NetworkClient
import time

network = NetworkClient()
print("Connecting...")
success = network.connect()
print("Connect Success:", success)
if success:
    print("Host:", network.host)
