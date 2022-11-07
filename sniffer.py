# Auchor : Abdulrahman Ayman  SOFTWARE ENGNEER ##
#################################################
# Sniffer Script 
#################################################
from scapy.all import *
from geoip import geolite2
import socket

#################################################
def getservByName(__Src_Port,__Dst_Port):
    try:
        serv = socket.getservbyport(__Src_Port)
    except:
        serv = socket.getservbyport(__Dst_Port)
    return serv
#################################################

##################################################
def locate(__IP):
    locateor = geolite2.lookup(__IP)
    if locateor is not None:
        return locateor.timezone, locateor.country
    else:
        return None
##################################################

##################################################
def analyzer(pkt):
    try:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ####################
        loc_src = locate(src_ip)
        loc_dst = locate(dst_ip)
        ########################

        if loc_src is not None:
            country = loc_src[0]
            timezone = loc_src[1] 
        elif loc_dst is not None:
            country = loc_dst[0]
            timezone = loc_dst[1]
        else:
            country = "Unknown"
            timezone = "Unknown"
        ##########################
        mac_src = pkt.src
        mac_dst = pkt.dst
        ##########################
        if pkt.haslayer(ICMP):
            print("----------------------------------------------------------------------")
            print("ICMP PACKET >>")
            print(f"Source Ip {src_ip} | Destenation Ip {dst_ip}")
            print(f"Source Mac {mac_src} | Destenation Mac {mac_dst}")
        # print(f"Source Port {str(src_port)} | Destenation Port {str(dst_port)}")
            print("Packet Size : "+str(len(pkt[ICMP])))
            if pkt.haslayer(Raw):
                print(pkt[Raw].load)
        else:
            src_port = pkt.sport
            dst_port = pkt.dport
            serv_port = getservByName(src_port,dst_port)
            if pkt.haslayer(TCP):
                print("----------------------------------------------------------------------")
                print("TCP PACKET >>")
                print(f"Source Ip {src_ip} | Destenation Ip {dst_ip}")
                print(f"Source Mac {mac_src} | Destenation Mac {mac_dst}")
                print(f"Source Port {str(src_port)} | Destenation Port {str(dst_port)}")
                print(f"Country {country} | Timezone {timezone}")
                print(f"Service {serv_port}")
                print("Packet Size : "+str(len(pkt[TCP])))
                if pkt.haslayer(Raw):
                    print(pkt[Raw].load)
            elif pkt.haslayer(UDP):
                print("----------------------------------------------------------------------")
                print("UDP PACKET >>")
                print(f"Source Ip {src_ip} | Destenation Ip {dst_ip}")
                print(f"Source Mac {mac_src} | Destenation Mac {mac_dst}")
                print(f"Source Port {str(src_port)} | Destenation Port {str(dst_port)}")
                print(f"Country {country} | Timezone {timezone}")
                print(f"Service {serv_port}")
                print("Packet Size : "+str(len(pkt[UDP])))
                if pkt.haslayer(Raw):
                    print(pkt[Raw].load)

    except:
        pass


print("-----------------------Started-----------------------")
sniff(iface="eth0",prn=analyzer)