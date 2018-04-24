#!/usr/bin/python

import socket
from thread import start_new_thread


def client_conn(conn, addr):
    conn.send("Welcome to my server. Please send me something.\r\n")
    while True:
        data = conn.recv(buff)
        print addr[0] + ' : ', data.strip()
        reply = 'Received... ' + data
        if not data:
            break
        conn.send(reply)
    conn.close()


s = socket.socket()
buff = 512
s.bind(('', 9992))
s.listen(5)

while True:
    conn, addr = s.accept()
    print "Connection received from %s on port %s" % (addr[0], addr[1])
    start_new_thread(client_conn, (conn, addr))
