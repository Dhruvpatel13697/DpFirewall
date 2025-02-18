import struct

import pydivert

import threading
from time import sleep
import socket
import scapy.all as scapy
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FirewallLogger")

class Firewall:
    def __init__(self, refresh_rate, icmp_packet_count, syn_packet_count):
        self.port_list = list()
        self.icmp_packets = {}
        self.syn_packets = {}
        self.refresh_rate = refresh_rate
        self.icmp_packet_count = icmp_packet_count
        self.syn_packet_count = syn_packet_count
        self.hostname = socket.gethostname()
        self.myIPAddr = socket.gethostbyname(self.hostname)
        self.filter = 'tcp.Syn or icmp'
        self.lock = threading.Lock()
        logger.info(f"Firewall initialized with IP: {self.myIPAddr}")

    @classmethod
    def create(cls, refresh_rate=10, icmp_packet_count=15, syn_packet_count=30):
        return cls(refresh_rate, icmp_packet_count, syn_packet_count)

    def run(self):
        self.running = True
        threading.Thread(target=self.sniff_arp_packets, daemon=True).start()
        threading.Thread(target=self.clear_firewall_buffer, daemon=True).start()
        try:
            with pydivert.WinDivert(self.filter) as w:
                for packet in w:
                    if not self.running:
                        break
                    self.handle_packet(w, packet)
        except KeyboardInterrupt:
            self.running = False
            logger.info("Firewall stopped.")

    def handle_packet(self, w, packet):
        try:
            if packet.dst_port in self.port_list:
                return
            if packet.icmp:
                self.detect_icmp_packets(w, packet)
            elif packet.tcp.syn:
                self.detect_syn_packet(w, packet)
            else:
                w.send(packet)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def detect_icmp_packets(self, w, packet):
        packet_ip = packet.src_addr
        dest_ip = packet.dst_addr
        packet_port = packet.src_port
        packet_dest_port = packet.dst_port
        logger.info(f"GOT A PING PACKET FROM {packet_ip}:{packet_port} to  {dest_ip}:{packet_dest_port} ")

        if packet_ip not in self.icmp_packets:
            self.icmp_packets[packet_ip] = 0

        self.icmp_packets[packet_ip] += 1

        if self.icmp_packets[packet_ip] > self.icmp_packet_count:
            logger.warning(f"Too many ping requests from: {packet_ip} dropping packets")

        else:
            w.send(packet)

    def detect_syn_packet(self, w, packet):
        packet_ip = packet.src_addr
        dest_ip = packet.dst_addr
        packet_port = packet.src_port
        packet_dest_port = packet.dst_port
        logger.info(f"GOT A SYN PACKET FROM {packet_ip}:{packet_port} to  {dest_ip}:{packet_dest_port} ")

        if packet_ip == self.myIPAddr:
            packet_ip = dest_ip

        if packet_ip not in self.syn_packets:
            self.syn_packets[packet_ip] = 0

        self.syn_packets[packet_ip] += 1

        if self.syn_packets[packet_ip] > self.syn_packet_count:
            logger.warning(f"Too many syn requests from: {packet_ip} dropping packets")

        else:
            w.send(packet)

    def clear_firewall_buffer(self):
        while True:
            sleep(self.refresh_rate * 60)
            self.icmp_packets = dict()
            self.syn_packets = dict()

    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        return answered_list[0][1].hwsrc

    def detect_arp_spoofing(self, pkt):
        try:
            if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
                pkt_s_ip = pkt[0][1].psrc
                pkt_s_mac = pkt[0][1].hwsrc
                real_mac = self.get_mac(pkt_s_ip)
                if real_mac != pkt_s_mac:
                    logger.warning(f"\nARP spoffing detected for ip {pkt_s_ip}, real mac is {real_mac}")
        except:
            pass

    def sniff_arp_packets(self):
        scapy.sniff(filter="arp", prn=lambda packet: self.detect_arp_spoofing(packet))


firewall_obj = Firewall.create()
firewall_obj.run()


#  pydivert api needs administrator privilegis