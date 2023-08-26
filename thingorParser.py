'''
Author: hxhBroFessor
Purpose: This script automates the extraction and summarization of service-related information from nmap output files.
         The primary functions are:
         1. Extract information of specific services based on defined patterns (like HTTPS, SMB, etc.).
         2. Collate a list of unique services from all the nmap files, excluding ones with unknown names.
         3. Extract services that have an indeterminate name (marked with a question mark).
         Results are written to individual text files for each service, providing a clear summary of hosts, ports, and versions.

'''

import os
import re
import sys

# Extract services from nmap files based on the type of service extraction
def extract_services_from_nmap_files(base_path, service_extraction_type, patterns=None):
    # Store service data
    services_data = {}

    # List all folders containing nmap files
    folders = [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]

    for folder in folders:
        nmap_file_path = os.path.join(base_path, folder, "nmap_output.nmap")

        if os.path.exists(nmap_file_path):
            try:
                with open(nmap_file_path, 'r') as file:
                    nmap_output = file.read()

                    # Extract host name or use default if not found
                    host_info = re.search(r"Nmap scan report for (.+)", nmap_output).group(1) if re.search(r"Nmap scan report for (.+)", nmap_output) else "Unknown host"

                    # Service extraction based on type
                    if service_extraction_type == "pattern":
                        for service, pattern in patterns.items():
                            for port, version in re.findall(pattern, nmap_output):
                                services_data.setdefault(service, []).append((host_info, port, version))
                    elif service_extraction_type == "unique":
                        for port, service, version in re.findall(r"(\d+/tcp)\s+open\s+(\w+)\s+(.+)", nmap_output):
                            if "?" not in service:
                                services_data.setdefault(service, set()).add((host_info, port, version))
                    elif service_extraction_type == "question":
                        for port, service in re.findall(r"(\d+/tcp)\s+open\s+([\w?]+)", nmap_output):
                            if "?" in service:
                                services_data.setdefault(service, set()).add((host_info, port, ""))
            except Exception as e:
                print(f"Error processing {nmap_file_path}: {e}")

    # Write extracted data to files
    for service, data in services_data.items():
        file_name = f"collected_{service.lower().replace('?', '')}_info.txt"
        with open(file_name, 'w') as output_file:
            output_file.write(f"Collected {service} Information:\n")
            for entry in data:
                output_file.write(f"Host: {entry[0]}\tPort: {entry[1]}\tVersion: {entry[2]}\n")
        print(f"{service} info written to {file_name}")


def main():
    service_patterns = {
        "HTTPS": r"(\d+/tcp)\s+open\s+ssl/http[s]?\s+(.+)",
        "SMB": r"(445/tcp)\s+open\s+(microsoft-ds\?)"
    }

    if len(sys.argv) != 2:
        print("Usage: python script.py <base_path>")
        sys.exit(1)

    base_path = sys.argv[1]

    extract_services_from_nmap_files(base_path, "pattern", service_patterns)
    extract_services_from_nmap_files(base_path, "unique")
    extract_services_from_nmap_files(base_path, "question")

if __name__ == "__main__":
    main()
