#!/usr/bin/python

from scapy.all import *

a = IP()
a.dst = '10.9.9.229'
b = ICMP()
p = a/b

resp = sr1(p,timeout=5)

if resp == None:
	print("The host is down")
else:
	print("The host is up")
