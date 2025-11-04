#!/usr/bin/env python3

import subprocess
import ipaddress
import re
import sys
import os
import argparse
import platform
import json
import csv
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- Main Functions ---

def get_os_type() -> str:
    """Returns the operating system type: 'Windows', 'Linux', or 'Darwin' (macOS)."""
    return platform.system()

def run_ping_to_update_arp(ip: str, verbose: bool = False) -> bool:
    """
    Pings the target IP to force the operating system to update its ARP table.
    Returns True if ping was successful, False otherwise.
    """
    try:
        os_type = get_os_type()
        
        if os_type == 'Windows':
            # Windows ping command: -n 1 (1 packet), -w 1000 (1 second timeout)
            cmd = ['ping', '-n', '1', '-w', '1000', ip]
        else:
            # Linux/Unix ping command: -c 1 (1 packet), -W 1 (1 second timeout)
            cmd = ['ping', '-c', '1', '-W', '1', ip]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        
        if verbose and result.returncode == 0:
            print(f"[DEBUG] Ping successful for {ip}")
            
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[DEBUG] Ping timeout for {ip}")
        return False
    except FileNotFoundError:
        print(f"[-] Error: 'ping' command not found. Ensure it is installed and in your PATH.")
        sys.exit(1)
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Ping error for {ip}: {e}")
        return False

def get_mac_from_arp_table(ip: str, verbose: bool = False) -> Optional[str]:
    """
    Reads the system's ARP table to find the MAC address for a given IP.
    Works on Windows, Linux, and macOS.
    """
    try:
        os_type = get_os_type()
        
        if os_type == 'Windows':
            # Windows: Use 'arp -a'
            arp_output = subprocess.check_output(['arp', '-a'], timeout=2).decode('utf-8', errors='ignore')
            # Windows format: 192.168.1.1          00-11-22-33-44-55     dynamic
            mac_regex = re.compile(r'\s+' + re.escape(ip) + r'\s+([0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})\s+', re.MULTILINE)
            match = mac_regex.search(arp_output)
            if match:
                # Convert Windows format (00-11-22-33-44-55) to standard format (00:11:22:33:44:55)
                return match.group(1).replace('-', ':')
        else:
            # Linux/macOS: Use 'arp -n'
            arp_output = subprocess.check_output(['arp', '-n'], timeout=2).decode('utf-8', errors='ignore')
            # Linux/macOS format: 192.168.1.1 ether 00:11:22:33:44:55 C eth0
            mac_regex = re.compile(r'^\s*' + re.escape(ip) + r'\s+.*\s+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})\s+.*$', re.MULTILINE)
            match = mac_regex.search(arp_output)
            if match:
                return match.group(1)
        
        if verbose:
            print(f"[DEBUG] No MAC found for {ip}")
        return None
            
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"[DEBUG] 'arp' command failed: {e}")
        return None
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[DEBUG] 'arp' command timeout for {ip}")
        return None
    except FileNotFoundError:
        print("[-] Error: 'arp' command not found. Ensure it is installed and in your PATH.")
        sys.exit(1)
    except Exception as e:
        if verbose:
            print(f"[DEBUG] ARP lookup error for {ip}: {e}")
        return None


def scan_single_host(ip_str: str, verbose: bool = False) -> Optional[Dict[str, str]]:
    """
    Scans a single host and returns its IP and MAC address if active.
    """
    # 1. Ping the host to populate the ARP cache
    ping_success = run_ping_to_update_arp(ip_str, verbose)
    
    # 2. Check the ARP table
    mac_address = get_mac_from_arp_table(ip_str, verbose)
    
    if mac_address:
        return {"ip": ip_str, "mac": mac_address, "responded": ping_success}
    
    return None

def scan_network(network_range: str, max_workers: int = 50, verbose: bool = False) -> List[Dict[str, str]]:
    """
    Scans the specified network range using ping and ARP table lookups.
    Uses multithreading for faster scanning.
    """
    active_hosts: List[Dict[str, str]] = []
    
    try:
        network = ipaddress.ip_network(network_range)
    except ValueError:
        print(f"[-] Invalid network range: {network_range}. Example: 192.168.1.0/24")
        return []

    total_hosts = network.num_addresses - 2  # Exclude network and broadcast addresses
    print(f"[+] Scanning network: {network_range}")
    print(f"[+] Total hosts to scan: {total_hosts}")
    print(f"[+] Using {max_workers} threads")
    print(f"[+] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    scanned = 0
    
    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scan jobs
        future_to_ip = {
            executor.submit(scan_single_host, str(ip), verbose): str(ip) 
            for ip in network.hosts()
        }
        
        # Process results as they complete
        for future in as_completed(future_to_ip):
            scanned += 1
            ip = future_to_ip[future]
            
            try:
                result = future.result()
                if result:
                    active_hosts.append(result)
                    print(f"[+] Found: {result['ip']:<16} -> {result['mac']}")
                
                # Progress indicator
                if scanned % 10 == 0 or scanned == total_hosts:
                    progress = (scanned / total_hosts) * 100
                    print(f"[*] Progress: {scanned}/{total_hosts} ({progress:.1f}%)")
                    
            except Exception as exc:
                if verbose:
                    print(f"[-] Error scanning {ip}: {exc}")

    print(f"\n[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return active_hosts

def print_results(hosts: List[Dict[str, str]]) -> None:
    """Prints the discovered hosts in a clean table format."""
    print("\n" + "="*65)
    print(f" {'IP Address':<20} {'MAC Address':<20} {'Status':<10}")
    print("="*65)
    
    if not hosts:
        print(" No active hosts found.")
        print("="*65)
        return

    for host in hosts:
        status = "Responded" if host.get('responded', False) else "ARP Only"
        print(f" {host['ip']:<20} {host['mac']:<20} {status:<10}")
    
    print("="*65)
    print(f" Total active hosts: {len(hosts)}")
    print("="*65)

def save_to_json(hosts: List[Dict[str, str]], filename: str) -> None:
    """Saves the results to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump({
                'scan_time': datetime.now().isoformat(),
                'total_hosts': len(hosts),
                'hosts': hosts
            }, f, indent=2)
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Error saving JSON file: {e}")

def save_to_csv(hosts: List[Dict[str, str]], filename: str) -> None:
    """Saves the results to a CSV file."""
    try:
        with open(filename, 'w', newline='') as f:
            if hosts:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'responded'])
                writer.writeheader()
                writer.writerows(hosts)
            print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Error saving CSV file: {e}")

def main():
    """Handles command-line arguments and script execution."""
    
    # Check for administrator/root privilege only on Unix systems
    if get_os_type() != 'Windows' and os.geteuid() != 0:
        print("[-] This script may require root privileges on Linux/macOS for best results.")
        print("[-] Consider running with 'sudo' if you encounter issues.")
        print()

    parser = argparse.ArgumentParser(
        description="A cross-platform network scanner using ping and ARP cache lookup.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.0/24
  %(prog)s -t 10.0.0.0/24 -w 100 -v
  %(prog)s -t 192.168.1.0/24 -o json -f scan_results.json
  %(prog)s -t 192.168.1.0/24 -o csv -f scan_results.csv
        """
    )
    parser.add_argument(
        '-t', '--target', dest='target_range', required=True,
        help='Target IP range in CIDR notation (e.g., 192.168.1.0/24)'
    )
    parser.add_argument(
        '-w', '--workers', dest='workers', type=int, default=50,
        help='Number of concurrent threads (default: 50)'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose output for debugging'
    )
    parser.add_argument(
        '-o', '--output', dest='output_format', choices=['json', 'csv'],
        help='Output format (json or csv)'
    )
    parser.add_argument(
        '-f', '--file', dest='output_file',
        help='Output filename (required if -o is specified)'
    )
    
    args = parser.parse_args()
    
    # Validate output arguments
    if args.output_format and not args.output_file:
        parser.error("-f/--file is required when -o/--output is specified")
    
    # Display system information
    print(f"[+] Operating System: {get_os_type()}")
    print(f"[+] Python Version: {sys.version.split()[0]}")
    print()
    
    # Perform the scan
    discovered_hosts = scan_network(args.target_range, args.workers, args.verbose)
    
    # Display results
    print_results(discovered_hosts)
    
    # Save to file if requested
    if args.output_format and args.output_file:
        if args.output_format == 'json':
            save_to_json(discovered_hosts, args.output_file)
        elif args.output_format == 'csv':
            save_to_csv(discovered_hosts, args.output_file)

if __name__ == "__main__":
    main()