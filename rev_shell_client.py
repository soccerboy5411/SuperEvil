import socket
import base64
from thread import start_new_thread

def shell():
    # Base64 decoded shell
    s = socket.socket()
    s.bind(('',443))
    s.listen(5)
    conn, addr = s.accept()
    print "Connection received from %s on port %s" % (addr[0], addr[1])
    start_new_thread(client_conn, (conn, addr, 1024))
    data = conn.recv(1024)
    print addr[0]+':', data

    decoded = base64.b64decode(data)
    s.close()
