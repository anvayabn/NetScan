import ipaddress
from os import walk

import scapy.all as scapy

DEFAULT_NETWORK_ADDRESS = "192.168.1.0"
DEFAULT_SUBNET_MASK = "24"
DEBUG_DISPLAY_ALL_ADDRESSES = False
DEBUG = True

SRC_IP_ADDRESS = "192.168.1.1"
SRC_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
DST_IP_ADDRESS = "192.168.1.2"
DST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
ARP_TYPE = 0x0806


class Lt_Packet:
    def __init__(self, ether, arp):
        self.ether = ether
        self.arp = arp
        self.pkt = None

    def make_l2_packet(self):
        if not self.pkt:
            if self.ether and self.arp:
                self.pkt = self.ether / self.arp
                return self.pkt
            else:
                return None

    def display_packet(self):
        if self.pkt:
            print(f"{self.pkt.show()}")


class Ether_layer:
    def __init__(self):
        self.dst = None
        self.src = None
        self.typ = None
        self.e_layer = None

    def set_dst_mac(self, dest_mac):
        self.dst = dest_mac

    def set_src_mac(self, src_mac):
        self.src = src_mac

    def set_type(self, prot_typ):
        self.typ = prot_typ

    def make_ether_frame(self):
        if not self.dst or not self.src or not self.typ or self.e_layer:
            return None
        else:
            self.e_layer = scapy.Ether(dst=self.dst, src=self.src, type=self.typ)
            return self.e_layer

    def display_elayer(self):
        if self.e_layer:
            print(f"{self.e_layer}")


class Arp_pkt:
    def __init__(self):
        self.hwtype = 1
        self.ptype = 0x800
        self.hwlen = 6
        self.plen = 4
        self.op = 1
        self.hwsrc = None
        self.psrc = None
        self.hwdst = None
        self.pdst = None
        self.Arp_pkt = None

    def set_src_mac(self, sender_mac):
        self.hwsrc = sender_mac

    def set_dst_mac(self, target_mac):
        self.hwdst = target_mac

    def set_src_ip(self, sender_ip):
        self.psrc = sender_ip

    def set_dst_ip(self, target_ip):
        self.pdst = target_ip

    def make_arp_packet(self):
        if not self.hwsrc or not self.psrc or not self.hwdst or not self.pdst:
            return None
        self.Arp_pkt = scapy.ARP(
            hwtype=self.hwtype,
            ptype=self.ptype,
            hwlen=self.hwlen,
            plen=self.plen,
            op=self.op,
            hwsrc=self.hwsrc,
            psrc=self.psrc,
            hwdst=self.hwdst,
            pdst=self.pdst,
        )
        return self.Arp_pkt

    def display_arp(self):
        if self.Arp_pkt:
            print(f"{self.Arp_pkt}")


def construct_l2frame(src_mac, src_ip, dst_mac, dst_ip):
    # Construct ARP packet
    arp = Arp_pkt()
    arp.set_src_ip(src_ip)
    arp.set_src_mac(src_mac)
    arp.set_dst_ip(dst_ip)
    arp.set_dst_mac(dst_mac)
    arp_layer = arp.make_arp_packet()

    # Construct Ethernet frame
    ether = Ether_layer()
    ether.set_dst_mac(dst_mac)
    ether.set_src_mac(src_mac)
    ether.set_type(ARP_TYPE)  # ARP protocol type
    ether_layer = ether.make_ether_frame()

    # Check if layers were created successfully
    if not ether_layer or not arp_layer:
        print("Error creating Ethernet or ARP layer.")
        return None

    # Combine layers into a packet
    pkt = Lt_Packet(ether_layer, arp_layer)
    pkt.make_l2_packet()

    if DEBUG:
        pkt.display_packet()


def main():
    IP_ADDRESS = DEFAULT_NETWORK_ADDRESS + "/" + DEFAULT_SUBNET_MASK
    netwrk_addr = ipaddress.IPv4Network(IP_ADDRESS)

    if DEBUG_DISPLAY_ALL_ADDRESSES:
        for ip in netwrk_addr:
            print(f"{ip}")

    # Construct the ARP and Ethernet packet
    construct_l2frame(SRC_MAC_ADDRESS, SRC_IP_ADDRESS, DST_MAC_ADDRESS, DST_IP_ADDRESS)
    # send packet
    # scapy.sendp(pkt, verbose=0)


if __name__ == "__main__":
    main()
