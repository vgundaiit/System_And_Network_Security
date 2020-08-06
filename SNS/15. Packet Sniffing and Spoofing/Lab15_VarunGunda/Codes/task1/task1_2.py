#!/usr/bin/python
from scapy.all import *

a = IP()
a.src = '100.100.100.100'	
a.dst = '10.1.1.0'		
b = ICMP()
p = a/b
send(p)