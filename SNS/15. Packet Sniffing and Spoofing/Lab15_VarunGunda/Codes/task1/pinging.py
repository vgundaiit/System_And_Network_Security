#!/usr/bin/python

from scapy.all import *

answer = sr1(IP(dst='8.8.8.8')/TCP(dport=23))
print (answer.summary())

