#!/usr/bin/python
from scapy.all import *
def print_pkt(pkt):
	pkt.show()

#pkt = sniff(filter='icmp',prn=print_pkt)

#pkt = sniff(filter='ip and host 8.8.8.8 and tcp port 23', prn=print_pkt)
#pkt = sniff(filter='ip host 8.8.8.8', prn=print_pkt)

pkt = sniff(filter='net 8.8.8.0/24', prn=print_pkt)