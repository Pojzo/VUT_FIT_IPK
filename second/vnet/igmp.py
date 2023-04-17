from scapy.all import *
import scapy.contrib.igmp

p = IP(dst="127.0.0.1")/scapy.contrib.igmp.IGMP()
send(p)
