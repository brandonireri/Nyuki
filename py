#!/usr/bin/env python
import os
from scapy.all import *
 
def scan_wifi():
    interface = 'wlan0'  # replace with your wireless interface name
    pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC()) / Dot11Beacon(cap="ESS")
    wifi_list = []
    for i in range(1,11):
        print(f'Scanning on channel {i}')
        os.system(f'iwconfig {interface} channel {i}')
        ap_list = sniff(iface=interface, timeout=5, lfilter=lambda x:x.haslayer(Dot11Beacon))
        for ap in ap_list:
            if ap.info not in wifi_list:
                wifi_list.append(ap.info)
                print(f'Found wifi network: {ap.info.decode()}')
 
if __name__ == '__main__':
    scan_wifi()
