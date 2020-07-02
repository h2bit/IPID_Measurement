import csv
import socket
import requests
import scapy
import time
import struct
import json
import threading

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

my_extra_ip = '152.136.160.194'
my_intra_ip = '172.21.0.52'

z_payload = b''
reader = None

def prob_thread_template(nu):

    tar = []
    result = []
    n_un_accessable = 0

    with open('top-1m.csv', 'r') as f:
        reader = csv.reader(f)
        res = list(reader)[nu * 1000: (nu + 1) * 1000]
        for i in range(0, len(res)):
            tar.append(res[i][1])

    for i, t in enumerate(tar, 1):
        try:
            ip = socket.getaddrinfo(t, None)[0][4][0]
            
            response = requests.get('http://' + ip, timeout=(5, 5))

            send(IP(src=my_intra_ip, dst=ip) /
                ICMP(type=3, code=4, nexthopmtu=68) /
                IP(flags=2, src=ip, dst=my_extra_ip) /
                ICMP(type=0, code=0) /
                z_payload, iface='eth0', verbose=False)

            pkts = sniff(filter='tcp and ip[6]=0 and src ' + ip, count=20, timeout=5,
                 started_callback=lambda: requests.get('http://' + ip, timeout=(5, 5)))
            
            if len(pkts) >= 5:
                print(str(nu * 1000 + i) + ': ' + ip + ' ' + t + 'fragment')
                result.append(t)
            
            print(str(nu * 1000 + i) + ': ' + ip + ' ' + t)

        except Exception as e:
            print(str(nu * 1000 + i) + ': ' + t + ' unaccessable')
            n_un_accessable += 1

    jstr = json.dumps({'res': result, 'n_unaccess': n_un_accessable, 'n_res': len(result)})
    print(len(result))

    with open('res_%d.json' %  nu, 'w') as f:
        f.write(jstr)

if __name__ == '__main__':
        
    for i in range(0, 520):
        z_payload += struct.pack('B', 0)

    for i in range(0, 100):
        t = threading.Thread(target=prob_thread_template, args=(i, ), name=('T' + str(i)))
        t.start()
        time.sleep(0.05)
