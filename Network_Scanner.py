#!/usr/bin/env python

from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
import scapy.all as scapy
import optparse
import subprocess
import re


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="The IP and/or IP range(target) to be scanned in the network")
    options, arguements = parser.parse_args()
    return options


def scan(ip):
    arp_req = ARP(pdst = ip)
    broadcast =Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list, unanswered_list = scapy.srp(arp_req_broadcast, timeout = 1, verbose = False)

    clients = []
    for element in answered_list:
        hx = subprocess.call(["nslookup", element[1].psrc])
        print(hx)
        hx = hx[31:-18]
        print(hx)
        client_dict = {"ip" : element[1].psrc, "mac" : element[1].hwsrc}#, "hn" : subprocess.call(["nslookup", element[1].psrc])}
        clients.append(client_dict)
    return clients


def print_result(result_list):
    #print("IP\t\t\tMAC Address\t\t\tHostname")
    print("___________________________________________________")
    #for client in result_list:
    #    print(client["ip"] + "\t\t" + client["mac"])# + "\t\t" + client["hn"])


options = get_args()
ip = options.ip
scan_result = scan(ip)
print_result(scan_result)
