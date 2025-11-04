# Advanced Network Scanner (arpPing.py)

A cross-platform network scanner that discovers active hosts on your local network using ping and ARP cache lookup. Similar to `netdiscover`, but works on Windows, Linux, and macOS with enhanced features including multithreading, progress tracking, and multiple output formats.

## Features ✨

- 🌐 **Cross-Platform Support** - Works on Windows, Linux, and macOS
- ⚡ **Fast Multithreaded Scanning** - Concurrent scanning with configurable thread count
- 📊 **Real-time Progress Tracking** - Live progress updates during scanning
- 💾 **Multiple Output Formats** - Save results as JSON or CSV
- 🐛 **Verbose Debug Mode** - Detailed debugging information
- 🎨 **Clean Table Output** - Well-formatted results display
- 📝 **Comprehensive Help** - Built-in help and examples

## Requirements

- Python 3.6 or higher
- Operating System: Windows, Linux, or macOS
- Standard system utilities: `ping` and `arp` commands

**Note:** On Linux/macOS, root privileges (`sudo`) may be required for best results.

## Installation

No additional packages required! Uses only Python standard library.

```bash
# Clone or download the script
git clone <repository-url>
cd <repository-directory>
```

## Usage

### Basic Scan
```bash
# Windows
python arpPing.py -t 192.168.1.0/24

# Linux/macOS (may require sudo)
sudo python3 arpPing.py -t 192.168.1.0/24
```

### Advanced Options

#### Fast Scan with More Threads
```bash
python arpPing.py -t 192.168.1.0/24 -w 100
```

#### Verbose Mode for Debugging
```bash
python arpPing.py -t 192.168.1.0/24 -v
```

#### Save Results to JSON
```bash
python arpPing.py -t 192.168.1.0/24 -o json -f scan_results.json
```

#### Save Results to CSV
```bash
python arpPing.py -t 192.168.1.0/24 -o csv -f scan_results.csv
```

#### Combine Multiple Options
```bash
python arpPing.py -t 10.0.0.0/24 -w 100 -v -o json -f results.json
```

## Command-Line Arguments

| Argument | Short | Description | Default | Required |
|----------|-------|-------------|---------|----------|
| `--target` | `-t` | Target IP range in CIDR notation (e.g., 192.168.1.0/24) | - | ✅ Yes |
| `--workers` | `-w` | Number of concurrent threads | 50 | ❌ No |
| `--verbose` | `-v` | Enable verbose output for debugging | False | ❌ No |
| `--output` | `-o` | Output format: `json` or `csv` | - | ❌ No |
| `--file` | `-f` | Output filename (required if `-o` is used) | - | ⚠️ Conditional |
| `--help` | `-h` | Show help message and exit | - | ❌ No |

## Output Example

```
[+] Operating System: Windows
[+] Python Version: 3.11.0

[+] Scanning network: 192.168.1.0/24
[+] Total hosts to scan: 254
[+] Using 50 threads
[+] Starting scan at 2025-11-05 14:30:00

[+] Found: 192.168.1.1      -> aa:bb:cc:dd:ee:ff
[+] Found: 192.168.1.100    -> 11:22:33:44:55:66
[*] Progress: 10/254 (3.9%)
[+] Found: 192.168.1.254    -> 99:88:77:66:55:44
[*] Progress: 254/254 (100.0%)

[+] Scan completed at 2025-11-05 14:30:45

=================================================================
 IP Address           MAC Address          Status    
=================================================================
 192.168.1.1          aa:bb:cc:dd:ee:ff    Responded 
 192.168.1.100        11:22:33:44:55:66    Responded 
 192.168.1.254        99:88:77:66:55:44    ARP Only  
=================================================================
 Total active hosts: 3
=================================================================
```

## JSON Output Format

```json
{
  "scan_time": "2025-11-05T14:30:45.123456",
  "total_hosts": 3,
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "responded": true
    },
    {
      "ip": "192.168.1.100",
      "mac": "11:22:33:44:55:66",
      "responded": true
    },
    {
      "ip": "192.168.1.254",
      "mac": "99:88:77:66:55:44",
      "responded": false
    }
  ]
}
```

## CSV Output Format

```csv
ip,mac,responded
192.168.1.1,aa:bb:cc:dd:ee:ff,True
192.168.1.100,11:22:33:44:55:66,True
192.168.1.254,99:88:77:66:55:44,False
```

## How It Works

1. **Ping Sweep**: Sends ICMP echo requests to each IP in the specified range
2. **ARP Cache Lookup**: Checks the system's ARP table for MAC addresses
3. **Multithreading**: Scans multiple hosts concurrently for faster results
4. **Cross-Platform**: Automatically detects OS and uses appropriate commands
   - Windows: `ping -n 1 -w 1000` and `arp -a`
   - Linux/macOS: `ping -c 1 -W 1` and `arp -n`

## Performance Tips

- **Increase threads** for faster scanning on large networks: `-w 100`
- **Smaller subnets** scan faster: use `/28` (14 hosts) instead of `/24` (254 hosts)
- **Verbose mode** slows down scanning but helps with debugging: `-v`

## Troubleshooting

### Linux/macOS: Permission Denied
```bash
# Run with sudo
sudo python3 arpPing.py -t 192.168.1.0/24
```

### No Hosts Found
- Ensure you're on the correct network
- Check firewall settings
- Verify the IP range is correct
- Try verbose mode to see what's happening: `-v`

### Slow Scanning
- Increase thread count: `-w 100`
- Some networks may block ICMP (ping)
- Use smaller subnet ranges

## License

MIT License - Feel free to use and modify!

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## Author

Network Security Enthusiast

---

**Disclaimer**: This tool is for educational and authorized network administration purposes only. Always ensure you have permission before scanning any network.