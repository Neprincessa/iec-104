import snap7
import time

server = snap7.server.Server()
server.create()
server.start()
while(1):
    print(server.get_status())
    time.sleep(10)
#time.sleep(10)
#server.get_status()

