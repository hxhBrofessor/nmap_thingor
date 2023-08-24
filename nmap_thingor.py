'''
Author: Bryan (hxhBroFessor)
Purpose: This repository contains a Python script designed to automate the process of running Nmap scans. 
          The script first performs a host discovery and then conducts a detailed port scan for each discovered host.
'''

import re
import subprocess
import os
import concurrent.futures

def start_nmap_scan(ip_cidr, output_file):
    command = f"sudo nmap -sn {ip_cidr} -oN {output_file}"
    subprocess.run(command, shell=True)

def create_folder(ip):
    folder_name = ip.replace(".", "_")
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

def merge_lines(input_file):
    with open(input_file, 'r') as f_in:
        lines = f_in.readlines()
        merged_lines = []

        i = 0
        while i < len(lines):
            if i + 1 < len(lines):
                line1 = lines[i].strip()
                line2 = lines[i + 1].strip()
                merged_line = f"{line1} {line2}"
                merged_lines.append(merged_line)
                i += 2
            else:
                merged_lines.append(lines[i])
                i += 1

    return merged_lines

def process_merged_lines(merged_lines):
    ip_addresses = []
    pattern = re.compile(r'Nmap scan report for (\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)')

    for line in merged_lines:
        if 'Nmap scan report' in line:
            match = pattern.search(line)
            if match:
                ip_address = match.group(2)
                ip_addresses.append(ip_address)
    return ip_addresses

def custom_sort(ip):
    return tuple(map(int, ip.split('.')))

def portScan(output_file, folder_name):
    command = f"sudo nmap -Pn -p- -sS -sV --open -T3 -iL {output_file} -oA {folder_name}/nmap_output"
    subprocess.run(command, shell=True)

def process_ip(ip):
    folder_name = create_folder(ip)
    ip_output_file = os.path.join(folder_name, "ip_scan.txt")
    with open(ip_output_file, "w") as f_out:
        f_out.write(ip + "\n")
    portScan(ip_output_file, folder_name)

def main():
    ip_cidr = input("Enter the IP/CIDR to scan (e.g., x.x.x.x/16): ")
    nmap_output_file = "x.x.x_host_enum.txt"

    print("Starting initial nmap scan...")
    start_nmap_scan(ip_cidr, nmap_output_file)

    print("Merging lines from nmap output...")
    merged_lines = merge_lines(nmap_output_file)
    print("Merging completed.")

    print("Processing merged lines...")
    ip_addresses = process_merged_lines(merged_lines)
    print("Processing completed..")

    print("Starting PortScan....")
    sorted_ips = sorted(ip_addresses, key=custom_sort)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(process_ip, sorted_ips)

    print("Nmap scans completed and results saved in respective folders.")

if __name__ == "__main__":
    main()
