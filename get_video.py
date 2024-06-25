import os
import sys
import socket

drone_tcp = ('172.16.10.1', 8888)

start_conv   = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x25\x25"
request_h264 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x28\x28"

#os.system("nmcli connection up TSRC-8f5314")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(drone_tcp)
sock.sendall(start_conv)

while True:
    sock.sendall(request_h264)
    sys.stdout.buffer.write(sock.recv(128))
