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
import socket
import time
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- Main Functions ---

def get_os_type() -> str:
    """Returns the operating system type: 'Windows', 'Linux', or 'Darwin' (macOS)."""
    return platform.system()

def send_notification(title: str, message: str) -> None:
    """
    Sends a desktop notification.
    Works on Windows, Linux, and macOS.
    """
    try:
        os_type = get_os_type()
        
        if os_type == 'Windows':
            # Windows 10/11 Toast Notification
            try:
                # Try using PowerShell for Windows toast notifications
                ps_command = f'''
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
                $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                $RawXml = [xml] $Template.GetXml()
                ($RawXml.toast.visual.binding.text|where {{$_.id -eq "1"}}).AppendChild($RawXml.CreateTextNode("{title}")) > $null
                ($RawXml.toast.visual.binding.text|where {{$_.id -eq "2"}}).AppendChild($RawXml.CreateTextNode("{message}")) > $null
                $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
                $SerializedXml.LoadXml($RawXml.OuterXml)
                $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
                $Toast.Tag = "arpPing"
                $Toast.Group = "NetworkScanner"
                $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("arpPing Network Scanner")
                $Notifier.Show($Toast)
                '''
                subprocess.run(['powershell', '-Command', ps_command], 
                             capture_output=True, timeout=2)
            except:
                # Fallback to simple console message
                print(f"\n[NOTIFICATION] {title}: {message}")
                
        elif os_type == 'Linux':
            # Linux notify-send
            subprocess.run(['notify-send', title, message], 
                         capture_output=True, timeout=2)
        elif os_type == 'Darwin':
            # macOS osascript
            subprocess.run(['osascript', '-e', 
                          f'display notification "{message}" with title "{title}"'],
                         capture_output=True, timeout=2)
    except Exception as e:
        # Silent fail - notifications are not critical
        pass

def get_device_type(mac: str, hostname: Optional[str], open_ports: List[int]) -> str:
    """
    Attempts to fingerprint the device type based on MAC vendor, hostname, and open ports.
    """
    mac_upper = mac.upper()
    hostname_lower = hostname.lower() if hostname else ""
    
    # MAC Vendor patterns (first 6 characters of MAC)
    mac_vendors = {
        'APPLE': ['00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:0D:93', '00:10:FA',
                 '00:11:24', '00:14:51', '00:16:CB', '00:17:F2', '00:19:E3', '00:1B:63',
                 '00:1C:B3', '00:1D:4F', '00:1E:52', '00:1E:C2', '00:1F:5B', '00:1F:F3',
                 '00:21:E9', '00:22:41', '00:23:12', '00:23:32', '00:23:6C', '00:23:DF',
                 '00:24:36', '00:25:00', '00:25:4B', '00:25:BC', '00:26:08', '00:26:4A',
                 '00:26:B0', '00:26:BB', '3C:15:C2', '40:6C:8F', '58:55:CA', '5C:95:AE',
                 '68:5B:35', '70:CD:60', '78:31:C1', '84:38:35', '88:66:5A', '8C:85:90',
                 '90:27:E4', '94:F6:A3', '98:01:A7', 'A4:5E:60', 'AC:3C:0B', 'B8:E8:56',
                 'BC:3B:AF', 'D0:25:98', 'D4:9A:20', 'DC:2B:2A', 'F0:DB:E2', 'F0:F6:1C'],
        'SAMSUNG': ['00:00:F0', '00:12:47', '00:12:FB', '00:13:77', '00:15:99', '00:15:B9',
                   '00:16:32', '00:16:6B', '00:16:6C', '00:17:C9', '00:17:D5', '00:18:AF',
                   '00:1A:8A', '00:1B:98', '00:1C:43', '00:1D:25', '00:1E:7D', '00:1E:E1',
                   '00:1E:E2', '00:21:19', '00:21:4C', '00:23:39', '00:23:D6', '00:23:D7',
                   '00:24:54', '00:24:90', '00:24:91', '00:25:38', '00:26:37', '34:08:BC',
                   '38:AA:3C', '5C:0A:5B', '68:EB:AE', 'AC:36:13', 'B4:07:F9', 'C8:19:F7',
                   'CC:3A:61', 'D0:22:BE', 'E8:50:8B', 'EC:1D:8B', 'F8:04:2E'],
        'RASPBERRY_PI': ['B8:27:EB', 'DC:A6:32', 'E4:5F:01'],
        'XIAOMI': ['34:CE:00', '64:09:80', '78:11:DC', '8C:BE:BE', 'F4:8E:92'],
        'HUAWEI': ['00:18:82', '00:1E:10', '00:25:9E', '00:46:4B', '00:66:4B', '00:E0:FC',
                  '28:6E:D4', '48:7D:2E', '64:3E:8C', '68:3E:34', '6C:4A:85', '84:A8:E4'],
        'TP_LINK': ['00:27:19', '10:FE:ED', '14:CF:92', '50:C7:BF', '64:70:02', '90:F6:52',
                   'A0:F3:C1', 'C0:25:E9', 'D8:0D:17', 'E8:94:F6', 'F4:EC:38'],
        'CISCO': ['00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64', '00:01:96',
                 '00:01:97', '00:01:C7', '00:01:C9', '00:02:16', '00:02:17', '00:02:3D']
    }
    
    # Check MAC vendor
    mac_prefix = ':'.join(mac_upper.split(':')[:3])
    device_type = "Unknown"
    
    for vendor, prefixes in mac_vendors.items():
        if mac_prefix in prefixes:
            if vendor == 'APPLE':
                # Determine if it's iPhone, iPad, or Mac
                if hostname_lower:
                    if 'iphone' in hostname_lower:
                        device_type = "iPhone"
                    elif 'ipad' in hostname_lower:
                        device_type = "iPad"
                    elif 'macbook' in hostname_lower or 'imac' in hostname_lower:
                        device_type = "Mac Computer"
                    else:
                        device_type = "Apple Device"
                else:
                    device_type = "Apple Device"
            elif vendor == 'SAMSUNG':
                if 22 in open_ports or 80 in open_ports:
                    device_type = "Samsung Smart Device"
                else:
                    device_type = "Samsung Phone/Tablet"
            elif vendor == 'RASPBERRY_PI':
                device_type = "Raspberry Pi"
            elif vendor == 'XIAOMI':
                device_type = "Xiaomi Device"
            elif vendor == 'HUAWEI':
                device_type = "Huawei Device"
            elif vendor == 'TP_LINK':
                device_type = "TP-Link Router/AP"
            elif vendor == 'CISCO':
                device_type = "Cisco Network Device"
            break
    
    # Hostname-based detection
    if device_type == "Unknown" and hostname_lower:
        if 'android' in hostname_lower:
            device_type = "Android Device"
        elif 'iphone' in hostname_lower or 'ipad' in hostname_lower:
            device_type = "iOS Device"
        elif 'windows' in hostname_lower or 'desktop' in hostname_lower or 'laptop' in hostname_lower:
            device_type = "Windows Computer"
        elif 'linux' in hostname_lower or 'ubuntu' in hostname_lower:
            device_type = "Linux Computer"
        elif 'router' in hostname_lower:
            device_type = "Router"
        elif 'printer' in hostname_lower:
            device_type = "Printer"
        elif 'camera' in hostname_lower or 'cam' in hostname_lower:
            device_type = "Camera"
        elif 'tv' in hostname_lower or 'smart' in hostname_lower:
            device_type = "Smart TV"
    
    # Port-based detection
    if device_type == "Unknown" and open_ports:
        if 22 in open_ports and 80 in open_ports:
            device_type = "Server/IoT Device"
        elif 3389 in open_ports:
            device_type = "Windows Computer (RDP)"
        elif 22 in open_ports:
            device_type = "Linux/Unix Device"
        elif 445 in open_ports:
            device_type = "Windows Device (SMB)"
        elif 80 in open_ports or 443 in open_ports:
            device_type = "Web Server/IoT"
        elif 5900 in open_ports:
            device_type = "VNC Server"
    
    return device_type

def get_network_topology(hosts: List[Dict[str, any]]) -> Dict[str, any]:
    """
    Analyzes discovered hosts to determine network topology.
    Identifies gateway, subnet info, and device distribution.
    """
    if not hosts:
        return {}
    
    # Get IP addresses
    ips = [host['ip'] for host in hosts]
    
    # Determine subnet
    try:
        # Find the most common subnet
        ip_objs = [ipaddress.ip_address(ip) for ip in ips]
        first_ip = str(ip_objs[0])
        
        # Guess subnet based on first IP
        octets = first_ip.split('.')
        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        
        # Identify likely gateway (usually .1 or lowest IP)
        gateway_candidates = [ip for ip in ips if ip.endswith('.1')]
        gateway = gateway_candidates[0] if gateway_candidates else ips[0]
        
        # Count device types
        device_types = {}
        for host in hosts:
            dtype = host.get('device_type', 'Unknown')
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        # Identify servers (devices with many open ports)
        servers = []
        for host in hosts:
            if 'open_ports' in host and len(host.get('open_ports', [])) >= 3:
                servers.append({
                    'ip': host['ip'],
                    'hostname': host.get('hostname', 'Unknown'),
                    'ports': len(host.get('open_ports', []))
                })
        
        topology = {
            'subnet': subnet,
            'gateway': gateway,
            'total_devices': len(hosts),
            'device_types': device_types,
            'servers': servers,
            'ip_range': f"{min(ips)} - {max(ips)}"
        }
        
        return topology
        
    except Exception:
        return {}

def get_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    """
    Attempts to resolve the hostname for a given IP address.
    Returns the hostname if found, None otherwise.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return None
    except Exception:
        return None

def scan_ports(ip: str, ports: List[int], timeout: float = 0.5) -> List[int]:
    """
    Scans the specified ports on the target IP.
    Returns a list of open ports.
    """
    open_ports = []
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
    
    return open_ports

def get_port_service_name(port: int) -> str:
    """Returns common service names for well-known ports."""
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    return common_ports.get(port, f"Port-{port}")

def get_service_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Attempts to grab the service banner from an open port.
    Returns the banner string if available.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send a generic request for HTTP-based services
        if port in [80, 8080, 8443]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 22:  # SSH
            pass  # SSH sends banner automatically
        elif port == 21:  # FTP
            pass  # FTP sends banner automatically
        else:
            # Try to receive data anyway
            pass
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        # Clean up banner
        if banner:
            # Extract version info from common banner formats
            banner = banner.split('\n')[0][:100]  # First line, max 100 chars
            return banner
        
        return None
    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except Exception:
        return None

def check_vulnerabilities(service_info: Dict[str, any]) -> List[Dict[str, str]]:
    """
    Checks for known vulnerabilities based on service versions.
    Returns a list of vulnerability warnings.
    """
    vulnerabilities = []
    
    # Port-based vulnerability checks
    port = service_info.get('port', 0)
    banner = service_info.get('banner', '').lower() if service_info.get('banner') else ''
    
    # Telnet - Insecure protocol
    if port == 23:
        vulnerabilities.append({
            'severity': 'HIGH',
            'service': 'Telnet',
            'issue': 'Insecure protocol - transmits data in plaintext',
            'recommendation': 'Use SSH (port 22) instead'
        })
    
    # FTP - Insecure protocol
    if port == 21:
        vulnerabilities.append({
            'severity': 'MEDIUM',
            'service': 'FTP',
            'issue': 'Insecure protocol - credentials sent in plaintext',
            'recommendation': 'Use SFTP or FTPS instead'
        })
    
    # HTTP on standard web ports - No encryption
    if port in [80, 8080] and banner:
        vulnerabilities.append({
            'severity': 'MEDIUM',
            'service': 'HTTP',
            'issue': 'Unencrypted web traffic',
            'recommendation': 'Use HTTPS (port 443) instead'
        })
    
    # SMB v1 detection
    if port == 445:
        vulnerabilities.append({
            'severity': 'HIGH',
            'service': 'SMB',
            'issue': 'SMBv1 may be enabled (EternalBlue vulnerability)',
            'recommendation': 'Disable SMBv1 and use SMBv2/v3 only'
        })
    
    # VNC - Often has weak authentication
    if port == 5900:
        vulnerabilities.append({
            'severity': 'MEDIUM',
            'service': 'VNC',
            'issue': 'VNC may have weak or no authentication',
            'recommendation': 'Use strong passwords and VNC over SSH tunnel'
        })
    
    # RDP exposed to internet
    if port == 3389:
        vulnerabilities.append({
            'severity': 'MEDIUM',
            'service': 'RDP',
            'issue': 'RDP exposed - vulnerable to brute force attacks',
            'recommendation': 'Use VPN, enable NLA, or restrict access by IP'
        })
    
    # Check for old/vulnerable versions in banner
    if banner:
        # OpenSSH old versions
        if 'openssh' in banner:
            # Extract version
            import re
            version_match = re.search(r'openssh[_\s]+([\d.]+)', banner)
            if version_match:
                version = version_match.group(1)
                major_minor = '.'.join(version.split('.')[:2])
                try:
                    if float(major_minor) < 7.4:
                        vulnerabilities.append({
                            'severity': 'HIGH',
                            'service': f'OpenSSH {version}',
                            'issue': 'Outdated OpenSSH version with known vulnerabilities',
                            'recommendation': 'Upgrade to OpenSSH 8.0 or later'
                        })
                except ValueError:
                    pass
        
        # Apache old versions
        if 'apache' in banner:
            version_match = re.search(r'apache/([\d.]+)', banner)
            if version_match:
                version = version_match.group(1)
                major_minor = '.'.join(version.split('.')[:2])
                try:
                    if float(major_minor) < 2.4:
                        vulnerabilities.append({
                            'severity': 'HIGH',
                            'service': f'Apache {version}',
                            'issue': 'Outdated Apache version with known vulnerabilities',
                            'recommendation': 'Upgrade to Apache 2.4.x or later'
                        })
                except ValueError:
                    pass
        
        # nginx old versions
        if 'nginx' in banner:
            version_match = re.search(r'nginx/([\d.]+)', banner)
            if version_match:
                version = version_match.group(1)
                major_minor = '.'.join(version.split('.')[:2])
                try:
                    if float(major_minor) < 1.18:
                        vulnerabilities.append({
                            'severity': 'MEDIUM',
                            'service': f'nginx {version}',
                            'issue': 'Outdated nginx version',
                            'recommendation': 'Upgrade to nginx 1.20.x or later'
                        })
                except ValueError:
                    pass
    
    return vulnerabilities

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


def scan_single_host(ip_str: str, scan_ports_flag: bool = False, 
                     ports_to_scan: List[int] = None, 
                     resolve_hostname: bool = False,
                     fingerprint: bool = False,
                     vuln_check: bool = False,
                     verbose: bool = False) -> Optional[Dict[str, any]]:
    """
    Scans a single host and returns its IP, MAC address, hostname, and open ports if active.
    """
    # 1. Ping the host to populate the ARP cache
    ping_success = run_ping_to_update_arp(ip_str, verbose)
    
    # 2. Check the ARP table
    mac_address = get_mac_from_arp_table(ip_str, verbose)
    
    if mac_address:
        host_info = {
            "ip": ip_str, 
            "mac": mac_address, 
            "responded": ping_success
        }
        
        # 3. Resolve hostname if requested
        hostname = None
        if resolve_hostname or fingerprint:
            hostname = get_hostname(ip_str)
            host_info["hostname"] = hostname if hostname else "Unknown"
        
        # 4. Scan ports if requested
        open_ports = []
        if scan_ports_flag and ports_to_scan:
            open_ports = scan_ports(ip_str, ports_to_scan)
            host_info["open_ports"] = open_ports
            
            # 5. Get service banners and check vulnerabilities if requested
            if vuln_check and open_ports:
                banners = {}
                all_vulnerabilities = []
                
                for port in open_ports:
                    banner = get_service_banner(ip_str, port)
                    if banner:
                        banners[port] = banner
                    
                    # Check for vulnerabilities
                    service_info = {'port': port, 'banner': banner}
                    vulns = check_vulnerabilities(service_info)
                    if vulns:
                        all_vulnerabilities.extend(vulns)
                
                if banners:
                    host_info["banners"] = banners
                if all_vulnerabilities:
                    host_info["vulnerabilities"] = all_vulnerabilities
        
        # 6. Device fingerprinting if requested
        if fingerprint:
            device_type = get_device_type(mac_address, hostname, open_ports)
            host_info["device_type"] = device_type
        
        return host_info
    
    return None

def scan_network(network_range: str, max_workers: int = 50, 
                 scan_ports_flag: bool = False,
                 ports_to_scan: List[int] = None,
                 resolve_hostname: bool = False,
                 fingerprint: bool = False,
                 vuln_check: bool = False,
                 verbose: bool = False) -> List[Dict[str, any]]:
    """
    Scans the specified network range using ping and ARP table lookups.
    Uses multithreading for faster scanning.
    """
    active_hosts: List[Dict[str, any]] = []
    
    try:
        network = ipaddress.ip_network(network_range)
    except ValueError:
        print(f"[-] Invalid network range: {network_range}. Example: 192.168.1.0/24")
        return []

    total_hosts = network.num_addresses - 2  # Exclude network and broadcast addresses
    print(f"[+] Scanning network: {network_range}")
    print(f"[+] Total hosts to scan: {total_hosts}")
    print(f"[+] Using {max_workers} threads")
    if resolve_hostname:
        print(f"[+] Hostname resolution: Enabled")
    if scan_ports_flag:
        print(f"[+] Port scanning: Enabled ({len(ports_to_scan)} ports)")
    if fingerprint:
        print(f"[+] Device fingerprinting: Enabled")
    if vuln_check:
        print(f"[+] Vulnerability checking: Enabled")
    print(f"[+] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    scanned = 0
    
    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scan jobs
        future_to_ip = {
            executor.submit(scan_single_host, str(ip), scan_ports_flag, 
                          ports_to_scan, resolve_hostname, fingerprint, 
                          vuln_check, verbose): str(ip) 
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
                    
                    # Display found host
                    host_str = f"[+] Found: {result['ip']:<16} -> {result['mac']:<18}"
                    if fingerprint and 'device_type' in result:
                        host_str += f" [{result['device_type']}]"
                    if resolve_hostname and 'hostname' in result:
                        host_str += f" ({result['hostname']})"
                    if scan_ports_flag and 'open_ports' in result and result['open_ports']:
                        ports_str = ', '.join([f"{p}/{get_port_service_name(p)}" for p in result['open_ports']])
                        host_str += f" | Ports: {ports_str}"
                    print(host_str)
                    
                    # Display vulnerabilities if found
                    if vuln_check and 'vulnerabilities' in result and result['vulnerabilities']:
                        for vuln in result['vulnerabilities']:
                            print(f"    [!] {vuln['severity']}: {vuln['service']} - {vuln['issue']}")
                
                # Progress indicator
                if scanned % 10 == 0 or scanned == total_hosts:
                    progress = (scanned / total_hosts) * 100
                    print(f"[*] Progress: {scanned}/{total_hosts} ({progress:.1f}%)")
                    
            except Exception as exc:
                if verbose:
                    print(f"[-] Error scanning {ip}: {exc}")

    print(f"\n[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Print scan statistics
    if active_hosts:
        responded_count = sum(1 for h in active_hosts if h.get('responded', False))
        arp_only_count = len(active_hosts) - responded_count
        
        print(f"\n[*] Scan Statistics:")
        print(f"    - Responded to ping: {responded_count}/{len(active_hosts)}")
        print(f"    - ARP only: {arp_only_count}/{len(active_hosts)}")
        
        if fingerprint:
            device_types = {}
            for host in active_hosts:
                dtype = host.get('device_type', 'Unknown')
                device_types[dtype] = device_types.get(dtype, 0) + 1
            print(f"    - Unique device types: {len(device_types)}")
        
        if vuln_check:
            total_vulns = sum(len(host.get('vulnerabilities', [])) for host in active_hosts)
            if total_vulns > 0:
                high_vulns = sum(1 for host in active_hosts for v in host.get('vulnerabilities', []) if v['severity'] == 'HIGH')
                print(f"    - Vulnerabilities found: {total_vulns} (HIGH: {high_vulns})")
    
    return active_hosts

def print_results(hosts: List[Dict[str, any]], show_ports: bool = False, 
                  show_hostname: bool = False, show_fingerprint: bool = False,
                  show_topology: bool = False, show_vulns: bool = False) -> None:
    """Prints the discovered hosts in a clean table format."""
    
    # Determine column width based on options
    width = 65
    if show_hostname:
        width += 25
    if show_ports:
        width += 30
    if show_fingerprint:
        width += 25
    
    print("\n" + "="*width)
    
    # Print header
    header = f" {'IP Address':<20} {'MAC Address':<20} {'Status':<10}"
    if show_fingerprint:
        header += f" {'Device Type':<25}"
    if show_hostname:
        header += f" {'Hostname':<25}"
    if show_ports:
        header += f" {'Open Ports':<30}"
    print(header)
    print("="*width)
    
    if not hosts:
        print(" No active hosts found.")
        print("="*width)
        return

    for host in hosts:
        status = "Responded" if host.get('responded', False) else "ARP Only"
        row = f" {host['ip']:<20} {host['mac']:<20} {status:<10}"
        
        if show_fingerprint:
            device_type = host.get('device_type', 'Unknown')
            row += f" {device_type:<25}"
        
        if show_hostname:
            hostname = host.get('hostname', 'N/A')
            row += f" {hostname:<25}"
        
        if show_ports:
            if 'open_ports' in host and host['open_ports']:
                ports_str = ', '.join([str(p) for p in host['open_ports'][:5]])
                if len(host['open_ports']) > 5:
                    ports_str += '...'
            else:
                ports_str = 'None'
            row += f" {ports_str:<30}"
        
        print(row)
        
        # Print vulnerabilities if requested
        if show_vulns and 'vulnerabilities' in host and host['vulnerabilities']:
            for vuln in host['vulnerabilities']:
                severity_color = vuln['severity']
                print(f"     └─ [{severity_color}] {vuln['service']}: {vuln['issue']}")
                print(f"        → {vuln['recommendation']}")
    
    print("="*width)
    print(f" Total active hosts: {len(hosts)}")
    
    # Count vulnerabilities
    if show_vulns:
        total_vulns = sum(len(host.get('vulnerabilities', [])) for host in hosts)
        if total_vulns > 0:
            high_vulns = sum(1 for host in hosts for v in host.get('vulnerabilities', []) if v['severity'] == 'HIGH')
            medium_vulns = sum(1 for host in hosts for v in host.get('vulnerabilities', []) if v['severity'] == 'MEDIUM')
            print(f" Total vulnerabilities: {total_vulns} (HIGH: {high_vulns}, MEDIUM: {medium_vulns})")
    
    print("="*width)
    
    # Print topology information if requested
    if show_topology and hosts:
        topology = get_network_topology(hosts)
        if topology:
            print("\n" + "="*60)
            print(" NETWORK TOPOLOGY")
            print("="*60)
            print(f" Subnet:          {topology.get('subnet', 'Unknown')}")
            print(f" Gateway:         {topology.get('gateway', 'Unknown')}")
            print(f" IP Range:        {topology.get('ip_range', 'Unknown')}")
            print(f" Total Devices:   {topology.get('total_devices', 0)}")
            
            if topology.get('device_types'):
                print("\n Device Distribution:")
                for dtype, count in sorted(topology['device_types'].items(), key=lambda x: x[1], reverse=True):
                    print(f"   - {dtype}: {count}")
            
            if topology.get('servers'):
                print("\n Identified Servers:")
                for server in topology['servers']:
                    print(f"   - {server['ip']:<16} ({server['hostname']}) - {server['ports']} open ports")
            
            print("="*60)

def save_to_json(hosts: List[Dict[str, any]], filename: str) -> None:
    """Saves the results to a JSON file."""
    try:
        # Convert any set to list for JSON serialization
        hosts_serializable = []
        for host in hosts:
            host_copy = host.copy()
            if 'open_ports' in host_copy and isinstance(host_copy['open_ports'], set):
                host_copy['open_ports'] = list(host_copy['open_ports'])
            hosts_serializable.append(host_copy)
        
        with open(filename, 'w') as f:
            json.dump({
                'scan_time': datetime.now().isoformat(),
                'total_hosts': len(hosts),
                'hosts': hosts_serializable
            }, f, indent=2)
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Error saving JSON file: {e}")

def save_to_csv(hosts: List[Dict[str, any]], filename: str) -> None:
    """Saves the results to a CSV file."""
    try:
        with open(filename, 'w', newline='') as f:
            if hosts:
                # Determine all possible fields
                fieldnames = ['ip', 'mac', 'responded']
                if any('hostname' in h for h in hosts):
                    fieldnames.append('hostname')
                if any('open_ports' in h for h in hosts):
                    fieldnames.append('open_ports')
                
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                # Convert open_ports to string for CSV
                for host in hosts:
                    host_copy = host.copy()
                    if 'open_ports' in host_copy:
                        host_copy['open_ports'] = ','.join(map(str, host_copy['open_ports']))
                    writer.writerow(host_copy)
                    
            print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Error saving CSV file: {e}")

def detect_changes(previous_hosts: List[Dict[str, any]], 
                   current_hosts: List[Dict[str, any]]) -> Dict[str, List[Dict[str, any]]]:
    """
    Compares two scan results and detects new and departed hosts.
    Returns a dict with 'new' and 'departed' keys.
    """
    prev_ips = {host['ip'] for host in previous_hosts}
    curr_ips = {host['ip'] for host in current_hosts}
    
    new_ips = curr_ips - prev_ips
    departed_ips = prev_ips - curr_ips
    
    new_hosts = [h for h in current_hosts if h['ip'] in new_ips]
    departed_hosts = [h for h in previous_hosts if h['ip'] in departed_ips]
    
    return {'new': new_hosts, 'departed': departed_hosts}

def monitor_network(network_range: str, interval: int = 30, 
                   max_workers: int = 50,
                   scan_ports_flag: bool = False,
                   ports_to_scan: List[int] = None,
                   resolve_hostname: bool = False,
                   fingerprint: bool = False,
                   vuln_check: bool = False,
                   notify: bool = False,
                   verbose: bool = False) -> None:
    """
    Continuously monitors the network for changes.
    Alerts when new devices join or leave the network.
    """
    print(f"[+] Starting network monitoring mode")
    print(f"[+] Scan interval: {interval} seconds")
    if notify:
        print(f"[+] Desktop notifications: Enabled")
    print(f"[+] Press Ctrl+C to stop monitoring\n")
    
    previous_hosts = []
    scan_count = 0
    
    try:
        while True:
            scan_count += 1
            print(f"\n{'='*60}")
            print(f"[*] Scan #{scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*60}")
            
            current_hosts = scan_network(
                network_range, max_workers, scan_ports_flag, 
                ports_to_scan, resolve_hostname, fingerprint, 
                vuln_check, verbose
            )
            
            # Detect changes after first scan
            if scan_count > 1:
                changes = detect_changes(previous_hosts, current_hosts)
                
                if changes['new']:
                    print(f"\n[!] ALERT: {len(changes['new'])} new device(s) detected:")
                    for host in changes['new']:
                        msg = f"    [+] {host['ip']:<16} -> {host['mac']}"
                        if fingerprint and 'device_type' in host:
                            msg += f" [{host['device_type']}]"
                        if resolve_hostname and 'hostname' in host:
                            msg += f" ({host['hostname']})"
                        print(msg)
                    
                    # Send notification
                    if notify:
                        device_info = f"{changes['new'][0]['ip']}"
                        if len(changes['new']) == 1:
                            if 'device_type' in changes['new'][0]:
                                device_info += f" ({changes['new'][0]['device_type']})"
                            send_notification("New Device Detected", 
                                           f"Device connected: {device_info}")
                        else:
                            send_notification("New Devices Detected", 
                                           f"{len(changes['new'])} devices connected")
                
                if changes['departed']:
                    print(f"\n[!] ALERT: {len(changes['departed'])} device(s) left:")
                    for host in changes['departed']:
                        msg = f"    [-] {host['ip']:<16} -> {host['mac']}"
                        if fingerprint and 'device_type' in host:
                            msg += f" [{host['device_type']}]"
                        if resolve_hostname and 'hostname' in host:
                            msg += f" ({host['hostname']})"
                        print(msg)
                    
                    # Send notification
                    if notify:
                        device_info = f"{changes['departed'][0]['ip']}"
                        if len(changes['departed']) == 1:
                            if 'device_type' in changes['departed'][0]:
                                device_info += f" ({changes['departed'][0]['device_type']})"
                            send_notification("Device Disconnected", 
                                           f"Device left: {device_info}")
                        else:
                            send_notification("Devices Disconnected", 
                                           f"{len(changes['departed'])} devices left")
                
                if not changes['new'] and not changes['departed']:
                    print(f"\n[*] No changes detected")
            
            previous_hosts = current_hosts
            
            print(f"\n[*] Waiting {interval} seconds until next scan...")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n\n[+] Monitoring stopped by user")
        print(f"[+] Total scans performed: {scan_count}")

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
  %(prog)s -t 192.168.1.0/24 --hostname --ports --fingerprint
  %(prog)s -t 192.168.1.0/24 --ports --vuln-check
  %(prog)s -t 192.168.1.0/24 --topology
  %(prog)s -t 192.168.1.0/24 --monitor --interval 60 --notify
  %(prog)s -t 192.168.1.0/24 --fingerprint --hostname --ports --vuln-check --topology
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
    parser.add_argument(
        '--hostname', action='store_true',
        help='Resolve and display hostnames for discovered devices'
    )
    parser.add_argument(
        '--ports', action='store_true',
        help='Scan common ports on discovered devices'
    )
    parser.add_argument(
        '--port-list', dest='port_list',
        help='Custom port list to scan (comma-separated, e.g., "22,80,443")'
    )
    parser.add_argument(
        '--fingerprint', action='store_true',
        help='Identify device types (Apple, Samsung, Raspberry Pi, etc.)'
    )
    parser.add_argument(
        '--topology', action='store_true',
        help='Display network topology information (gateway, device distribution)'
    )
    parser.add_argument(
        '--monitor', action='store_true',
        help='Continuous monitoring mode - detect network changes'
    )
    parser.add_argument(
        '--interval', type=int, default=30,
        help='Monitoring interval in seconds (default: 30, only used with --monitor)'
    )
    parser.add_argument(
        '--notify', action='store_true',
        help='Enable desktop notifications for network changes (only with --monitor)'
    )
    parser.add_argument(
        '--vuln-check', action='store_true',
        help='Check for known vulnerabilities in discovered services (requires --ports)'
    )
    
    args = parser.parse_args()
    
    # Validate output arguments
    if args.output_format and not args.output_file:
        parser.error("-f/--file is required when -o/--output is specified")
    
    # Validate vuln-check requires ports
    if args.vuln_check and not args.ports:
        parser.error("--vuln-check requires --ports to be enabled")
    
    # Validate notify requires monitor
    if args.notify and not args.monitor:
        print("[!] Warning: --notify only works with --monitor mode")
    
    # Prepare port list
    ports_to_scan = None
    if args.ports:
        if args.port_list:
            try:
                ports_to_scan = [int(p.strip()) for p in args.port_list.split(',')]
            except ValueError:
                print("[-] Error: Invalid port list format. Use comma-separated numbers.")
                sys.exit(1)
        else:
            # Default common ports
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    # Display system information
    print(f"[+] Operating System: {get_os_type()}")
    print(f"[+] Python Version: {sys.version.split()[0]}")
    print()
    
    # Monitor mode or single scan
    if args.monitor:
        monitor_network(
            args.target_range, 
            args.interval,
            args.workers,
            args.ports,
            ports_to_scan,
            args.hostname,
            args.fingerprint,
            args.vuln_check,
            args.notify,
            args.verbose
        )
    else:
        # Perform single scan
        discovered_hosts = scan_network(
            args.target_range, 
            args.workers,
            args.ports,
            ports_to_scan,
            args.hostname,
            args.fingerprint,
            args.vuln_check,
            args.verbose
        )
        
        # Display results
        print_results(discovered_hosts, args.ports, args.hostname, 
                     args.fingerprint, args.topology, args.vuln_check)
        
        # Save to file if requested
        if args.output_format and args.output_file:
            if args.output_format == 'json':
                save_to_json(discovered_hosts, args.output_file)
            elif args.output_format == 'csv':
                save_to_csv(discovered_hosts, args.output_file)

if __name__ == "__main__":
    main()