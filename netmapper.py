import subprocess
import ipaddress
import sys
import argparse
import os

def run_nmap_scan(target, detailed=False):
    try:
        if detailed:
            command = ["nmap", "-sV", "-A", "-T5", "-p22,139", "--open", target]
        else:
            command = ["nmap", "-sn", target]

        result = subprocess.check_output(command, universal_newlines=True)
        return result
    except Exception as e:
        print(f"An error occurred while running nmap: {e}")
        sys.exit(1)

def parse_live_hosts(nmap_output):
    lines = nmap_output.split("\n")
    live_hosts = []
    for line in lines:
        if "Nmap scan report for" in line:
            ip = line.split(" ")[-1].strip("()")
            live_hosts.append(ip)
    return live_hosts

def generate_dot_file(target, live_hosts, detailed_outputs):
    dot_filename = f"{target.replace('/', '_')}.dot"
    if os.path.exists(dot_filename):
        with open(dot_filename, 'r') as f:
            existing_content = f.read()
    else:
        existing_content = ""

    with open(dot_filename, 'w') as f:
        f.write("digraph network_map {\n")
        f.write(f'  "{target}" [shape=box];\n')
        for host, details in zip(live_hosts, detailed_outputs):
            f.write(f'  "{target}" -> "{host}";\n')
            f.write(f'  subgraph cluster_{host.replace(".", "_")} {{\n')
            f.write(f'    label="{host}";\n')
            f.write(f'    "{host}" [shape=ellipse];\n')

            for line in details.split("\n"):
                if "/tcp" in line:
                    tokens = line.split()
                    if len(tokens) >= 4:
                        port, state, service, version = tokens[:4]
                    else:
                        port, state, service = tokens[:3]
                        version = "Unknown"

                    f.write(f'    "{host}:{port}" [shape=record, label="{{{port} | {service} | {version}}}"];\n')
                    f.write(f'    "{host}" -> "{host}:{port}";\n')

            f.write("  }\n")
        f.write("}\n")


def main():
    parser = argparse.ArgumentParser(description="Network Mapper")
    parser.add_argument("--cidr", type=str, help="CIDR range for scanning a single subnet")
    parser.add_argument("--list", type=str, help="Comma-separated list of CIDR ranges for scanning multiple subnets")
    args = parser.parse_args()

    if args.cidr:
        targets = [args.cidr]
    elif args.list:
        targets = args.list.split(",")
    else:
        print("Either --cidr or --list must be provided.")
        sys.exit(1)

    for target in targets:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            print(f"Invalid CIDR range: {target}")
            continue

        print(f"Scanning target: {target}")
        nmap_output = run_nmap_scan(target)
        live_hosts = parse_live_hosts(nmap_output)

        print(f"Live hosts in {target}: {live_hosts}")

        detailed_outputs = []
        for host in live_hosts:
            print(f"Running detailed scan on {host}")
            detailed_output = run_nmap_scan(host, detailed=True)
            print(f"Details for {host}:\n{detailed_output}")
            detailed_outputs.append(detailed_output)

        generate_dot_file(target, live_hosts, detailed_outputs)

if __name__ == "__main__":
    main()
