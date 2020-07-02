import socket
import scapy
import time

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

n_send = 100
tar = ['www.zhihu.com']
my_extra_ip = '152.136.160.194'
my_intra_ip = '172.21.0.52'
bind_if_name = 'eth0'

z_payload = b''
for i in range(0, 520):
    z_payload += struct.pack('B', 0)

for t in tar:
    ip = socket.getaddrinfo(t, None)[0][4][0]

    send_list = [IP(src=my_intra_ip, dst=ip, id=i) / ICMP() for i in range(0, n_send)]

    pkts = sniff(filter="icmp and src " + ip,
                         iface=bind_if_name, count=n_send, timeout=2, started_callback=
                         lambda: send(send_list, iface=bind_if_name, verbose=False))

    print(len(pkts))

    ipids = []
    for pk in pkts:
        ipids.append(pk[1].fields['id'])

    ipid_next = 0
    for i in range(1, n_send):
        # print(ipids[i])
        if ipids[i] - ipids[i - 1] >= 2:
            print(' ---- ' + str(ipids[i]))
            ipid_next += 1

    print(ipid_next)
