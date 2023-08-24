# NMAP Scanning Thingor

Python script designed to automate the process of running Nmap scans. The script first performs a host discovery and then conducts a detailed port scan for each discovered host.


## Prerequisites

- Python 3.x
- `nmap` tool installed on your system
- Sudo privileges (as some nmap scans require them)

## Usage

1. Ensure you have the necessary privileges to run the script.
2. Execute the script: python3 nmapScan.py

## Features

- **Host Discovery**: Identifies live hosts in the specified CIDR range.
- **Port Scanning**: Performs an in-depth port scan on discovered hosts.
- **Organized Output**: Saves the scan results in organized folders for each IP.
- **Threading**: Uses concurrent threads to speed up the scanning process.
