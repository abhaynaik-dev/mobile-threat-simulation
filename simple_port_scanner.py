#! /usr/bin/env python3

import argparse
import sys
import socket
from colorama import Fore


def parse_args():
    parser = argparse.ArgumentParser(description='Execute Port Scanning')
    parser.add_argument('-t', '--target', dest='host',
                        help='Victim\'s IP address for Port Scanning',
                        required=True)
    parser.add_argument('-p', '--ports', dest='port_range', default='1-65535',
                        help='Port range to scan, default is 1-65535 (all ports)')
    return parser.parse_args()


def scan_port(host, ports):
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)

            result = s.connect_ex((host, port))
            if result == 0:
                print(f"{GREEN}{host:5}:{format(port):5} is open {RESET}")
            s.close()
    except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
    except socket.error:
        print("\n Server not responding !!!!")
        sys.exit()


def execute():
    options = parse_args()
    host = options.host
    port_range = options.port_range
    start_port, end_port = port_range.split("-")
    start_port, end_port = int(start_port), int(end_port)
    ports = [p for p in range(start_port, end_port)]
    scan_port(host, ports)


if __name__ == "__main__":
    GREEN = Fore.GREEN
    RESET = Fore.RESET
    GRAY = Fore.LIGHTBLACK_EX
    execute()
