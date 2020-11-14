from iec104Server import *
from iec104_tcp_packets import *

server_ip = '127.0.0.1'
client = iec104_tcp_client(server_ip)
for p in plist:
    print(client.sendOne(p))
