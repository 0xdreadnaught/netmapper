import subprocess
import ipaddress
import sys

def run_nmap_scan(target):
    try:
        result = subprocess.check_output(["nmap", "-sn", target], universal_newlines=True)
        return result
    except Exception as e:
        print(f"An error occurred while running nmap: {e}")
        sys.exit(1)

def parse_live_hosts(nmap_output):
    lines = nmap_output.split("\n")
    live_hosts = []
    for line in lines:
        if "Nmap scan report for" in line:
            ip = line.split(" ")[-1]
            live_hosts.append(ip)
    return live_hosts

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 netmapper.py <CIDR>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        print("Invalid CIDR range.")
        sys.exit(1)

    print(f"Scanning target: {target}")
    nmap_output = run_nmap_scan(target)
    live_hosts = parse_live_hosts(nmap_output)

    print(f"Live hosts in {target}: {live_hosts}")

if __name__ == "__main__":
    main()

