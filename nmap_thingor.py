'''
Author: hxhBroFessor
Purpose: Description: This script automates Nmap scans.
It detects active hosts, scans their ports, and includes a function to scan IPs within a subnet, excluding specified live IPs.
'''

from concurrent.futures import ThreadPoolExecutor
import subprocess
import re
import os
from pathlib import Path
import ipaddress


# Define patterns to search in the nmap output for various services
patterns = {
    "HTTPS": r"(\d+/tcp)\s+open\s+ssl/http[s]?\s+(.+)",
    "HTTP": r"(\d+/tcp)\s+open\s+http\s+(.+)",
    "SMB": r"(445/tcp)\s+open\s+(microsoft-ds\?)"
}

# Initializing a dictionary to store the results of the scan for each service
services = {service: [] for service in patterns.keys()}

# Function to perform nmap scan on web services (HTTP/HTTPS) on the given IP and port
def web_service_scan(ip, port, base_folder, service_type):
    base_folder = Path(base_folder)
    output_file = base_folder / ip / f"{service_type.lower()}{port}_{ip}_nmap.txt"
    command = f'nmap {ip} -sV -p {port} --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN {output_file}'
    subprocess.run(command, shell=True)

# Function to perform nmap scan on a given IP address and save the results in the specified folder
def scan_ip(ip, base_folder):
    base_folder = Path(base_folder)
    output_folder = base_folder / ip
    output_folder.mkdir(parents=True, exist_ok=True)  # Create the necessary directories
    command = f"sudo nmap -Pn -p- -sS -sV --open -T4 {ip} -oA {output_folder / 'nmap_output'}"
    print(f"Executing: {command}")

    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    # Parse the output of the nmap scan and check for the services defined in patterns
    for line in result.stdout.split('\n'):
        for service, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                port_info = match.group(1)
                services[service].append({'ip': ip, 'port_info': port_info})

                if service in ['HTTP', 'HTTPS']:
                    protocol = 'http' if service == 'HTTP' else 'https'
                    with open(base_folder / f'{protocol}_hosts.txt', 'a') as f:
                        f.write(f'{protocol}://{ip}:{port_info.split("/")[0]}\n')
                    web_service_scan(ip, port_info.split("/")[0], base_folder, service)

    # Handle any errors during the scan
    if result.stderr:
        print(f"Error encountered while scanning {ip}:\n{result.stderr}")

    print("Completed nmap scan for:", ip)

# Function to perform a host discovery on the given subnet and scan all the discovered hosts
def scan_subnet(subnet, base_folder):
    base_folder = Path(base_folder)
    command = f"sudo nmap -sn {subnet} -oG -"
    print(f"Executing:Host Discovery {command}")
    result = subprocess.check_output(command, shell=True).decode()
    live_ips = [line.split()[1] for line in result.split("\n") if "Up" in line]

    # Save the discovered live IPs to a file
    with open(base_folder / "live_ips.txt", 'w') as f:
        f.write("\n".join(live_ips))

    # Use ThreadPoolExecutor to parallelize the scan of the discovered hosts
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        executor.map(scan_ip, live_ips, [base_folder] * len(live_ips))

    # After scanning the live IPs, scan the remaining ones
    scan_subnet_excluding_live_ips(subnet, live_ips, base_folder)

# Function to scan IPs in a subnet excluding the given live IPs
def scan_subnet_excluding_live_ips(subnet, live_ips, base_folder):
    base_folder = Path(base_folder)
    all_ips = [str(ip) for ip in ipaddress.ip_network(subnet)]
    ips_to_scan = list(set(all_ips) - set(live_ips))
    exclude_scan_folder = base_folder / "exclude_scan"
    exclude_scan_folder.mkdir(parents=True, exist_ok=True)

    # Use ThreadPoolExecutor to parallelize the scan of the IPs to scan
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        for ip in ips_to_scan:
            executor.submit(scan_ip, ip, exclude_scan_folder)

def main():
    print("Choose a scanning option:")
    print("1. Scan a single IP address.")
    print("2. Scan a subnet.")
    print("3. Exit.")

    choice = input("Enter your choice (1/2/3): ")

    # Exit option
    if choice == "3":
        print("Exiting...")
        return

    folder_name = input("Enter a base folder name for scan results: ")
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    if choice == "1":
        ip_to_scan = input("Enter the IP address to scan: ")
        scan_ip(ip_to_scan, folder_name)
        print("IP Scan completed!")
    elif choice == "2":
        subnet_to_scan = input("Enter the subnet to scan (e.g. 10.2.0.0/16): ")
        scan_subnet(subnet_to_scan, folder_name)
        print("Subnet Scan completed!")
    else:
        print("Invalid choice! Please choose a valid option.")

    print("Program completed.")

if __name__ == "__main__":
    main()
