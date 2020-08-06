#!/usr/bin/python

from scapy.all import *

a = IP()
a.dst = '8.8.8.8'
b = ICMP()
flag = True
ttl = 1
stops = []


for x in xrange(1,1000):
	pass
	a.ttl = ttl
	ans, unans = sr(a/b)
	#ICMP echo-reply
	if ans.res[0][1].type == 0:
		break
	#appending src ip to stops obtained from error message
	else:
		stops.append(ans.res[0][1].src)
		ttl+=1
i = 1
for hop in stops:
	print i," " + hop
	i+=1