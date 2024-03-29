import csv
import socket
import requests
import scapy
import time
import struct
import json

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

my_extra_ip = '152.136.160.194'
my_intra_ip = '172.21.0.52'
number = 1

tar = []
result = []
n_un_accessable = 0

with open('top-1m.csv', 'r') as f:
    reader = csv.reader(f)
    res = list(reader)[number * 10000: (number + 1) * 10000]
    for i in range(0, 10000):
        tar.append(res[i][1])

z_payload = b''
for i in range(0, 520):
    z_payload += struct.pack('B', 0)

for t in tar:
    try:
        ip = socket.getaddrinfo(t, None)[0][4][0]
        print(ip + ' ' + t)
        response = requests.get('http://' + ip, timeout=(5, 5))

        send(IP(src=my_intra_ip, dst=ip) /
            ICMP(type=3, code=4, nexthopmtu=68) /
            IP(flags=2, src=ip, dst=my_extra_ip) /
            ICMP(type=0, code=0) /
            z_payload, iface='eth0', verbose=False)

        pkts = sniff(filter='tcp and ip[6]=0', count=20, timeout=5,
             started_callback=lambda: requests.get('http://' + ip))
        if len(pkts) >= 5:
            print(t + ' fragment')
            result.append(t)

    except Exception as e:
        print(t + ' unaccessable')
        n_un_accessable += 1

jstr = json.dumps({'res': result, 'n_unaccess': n_un_accessable, 'n_res': len(result)})
print(len(result))

with open('res.json', 'w') as f:
    f.write(jstr)
