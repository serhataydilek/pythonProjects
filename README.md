# Simple Network Scanner (netscan.py)

This Python script performs a local network scan, similar to `netdiscover`, by leveraging standard Linux system commands (`ping` and `arp`) to find active hosts' IP and MAC addresses.

## Requirements
- Linux environment (e.g., Arch, Ubuntu)
- Root privileges (`sudo`)

## How to Run
1. Save the code as `netscan.py`.
2. Execute with root privileges, specifying your network range:
   ```bash
   sudo python3 netscan.py --target 192.168.1.0/24