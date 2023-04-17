import time
from scapy.all import *

src_ip = '192.168.1.100'
dst_ip = '10.0.2.15'


ip = IP(src=src_ip, dst=dst_ip)
icmp = ICMP()

payload = 'Kamarat, tak ty si dobry koko'

pkt = ip/icmp/Raw(load=payload)
send(pkt)
