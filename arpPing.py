#!/usr/bin/env python3

import subprocess
import ipaddress
import re
import sys
import os
import argparse
from typing import List, Dict, Optional

# --- Main Functions ---

def run_ping_to_update_arp(ip: str) -> None:
    """
    Pings the target IP to force the operating system to update its ARP table.
    -c 1: Send only 1 packet.
    -W 1: Wait for 1 second timeout.
    """
    try:
        # We suppress output as we only care about the side effect (ARP cache update)
        subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2  # Total command timeout
        )
    except subprocess.TimeoutExpired:
        # Ignore timeout errors for ping
        pass
    except FileNotFoundError:
        print(f"[-] Error: 'ping' command not found. Ensure it is installed and in your PATH.")
        sys.exit(1)

def get_mac_from_arp_table(ip: str) -> Optional[str]:
    """
    Reads the system's ARP table to find the MAC address for a given IP.
    """
    try:
        # Execute 'arp -n' (numeric output) to list the entire cache
        arp_output = subprocess.check_output(['arp', '-n'], timeout=1).decode('utf-8')
        
        # Regex to find the target IP followed by a MAC address
        # It looks for the IP, then any whitespace, then 6 pairs of hex digits separated by colons.
        # This regex is specifically tuned for Linux 'arp -n' output format
        mac_regex = re.compile(r'^\s*' + re.escape(ip) + r'\s+.*\s+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})\s+.*$', re.MULTILINE)
        
        match = mac_regex.search(arp_output)
        
        if match:
            return match.group(1)
        else:
            return None # IP not found in ARP cache
            
    except subprocess.CalledProcessError:
        print("[-] Error: 'arp' command failed to execute. Check permissions.")
        return None
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        print("[-] Error: 'arp' command not found. Ensure it is installed and in your PATH.")
        sys.exit(1)
    except Exception:
        return None


def scan_network(network_range: str) -> List[Dict[str, str]]:
    """
    Scans the specified network range using ping and ARP table lookups.
    """
    active_hosts: List[Dict[str, str]] = []
    
    try:
        network = ipaddress.ip_network(network_range)
    except ValueError:
        print(f"[-] Invalid network range: {network_range}. Example: 192.168.1.0/24")
        return []

    print(f"[+] Scanning network: {network_range}...")
    
    # Iterate through all usable host addresses in the network
    for ip in network.hosts():
        ip_str = str(ip)
        
        # 1. Ping the host to populate the ARP cache
        run_ping_to_update_arp(ip_str)
        
        # 2. Check the ARP table immediately after
        mac_address = get_mac_from_arp_table(ip_str)
        
        if mac_address:
            active_hosts.append({"ip": ip_str, "mac": mac_address})

    return active_hosts

def print_results(hosts: List[Dict[str, str]]) -> None:
    """Prints the discovered hosts in a clean table format."""
    print("\n" + "="*40)
    print(" IP Address\t\t\tMAC Address")
    print("="*40)
    
    if not hosts:
        print(" No active hosts found.")
        return

    for host in hosts:
        print(f" {host['ip']}\t\t{host['mac']}")
    print("="*40)

def main():
    """Handles command-line arguments and script execution."""
    
    # Check for root privilege (required for ping and arp access)
    if os.geteuid() != 0:
        print("[-] This script requires root privileges to run (for ping and arp table access).")
        print("[-] Please run with 'sudo'.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="A simple local network scanner (netdiscover-like) using ping and ARP cache lookup."
    )
    parser.add_argument(
        '-t', '--target', dest='target_range', required=True,
        help='Target IP range in CIDR notation (e.g., 192.168.1.0/24)'
    )
    
    args = parser.parse_args()
    
    discovered_hosts = scan_network(args.target_range)
    print_results(discovered_hosts)

if __name__ == "__main__":
    main()