import argparse
import json
import dns.resolver
import nmap
import shodan

def parse_args():
    parser = argparse.ArgumentParser(description="Automated Reconnaissance Tool")
    parser.add_argument('--ports', type=str, choices=['common', 'extended', 'all', 'custom'], default='common',
                        help="Port range to scan: 'common' (1-1024), 'extended' (1-12000), 'all' (0-65535), 'custom' (specify custom range)")
    parser.add_argument('--custom-ports', type=str, help="Custom port range (e.g., 80,443,8080) if --ports is set to 'custom'")
    parser.add_argument('--output', type=str, help="Output file for results")
    return parser.parse_args()

def load_api_keys():
    with open('config/api_keys.json') as f:
        return json.load(f)

api_keys = load_api_keys()
shodan_api_key = api_keys['shodan_api_key']
censys_api_id = api_keys['censys_api_id']
censys_secret = api_keys['censys_secret']

def load_subdomains():
    subdomains = []
    with open('subdomains.txt') as f:
        for line in f:
            domain = line.strip()
            if domain:
                subdomains.append(domain)
    return subdomains

def get_port_range(ports_option, custom_ports=None):
    if ports_option == 'common':
        return '1-1024'
    elif ports_option == 'extended':
        return '1-12000'
    elif ports_option == 'all':
        return '0-65535'
    elif ports_option == 'custom' and custom_ports:
        return custom_ports
    else:
        raise ValueError("Invalid port range selection or custom port range not provided.")

def scan_ports(target, port_range):
    nm = nmap.PortScanner()
    nm.scan(target, port_range)
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print("State:", nm[host].state())
        for proto in nm[host].all_protocols():
            print("Protocol:", proto)
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")

def shodan_vuln_scan(ip):
    api = shodan.Shodan(shodan_api_key)
    try:
        host = api.host(ip)
        for item in host['data']:
            if 'vulns' in item:
                for vuln in item['vulns']:
                    print(f"Vulnerability: {vuln}")
    except shodan.APIError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    args = parse_args()
    
    print("Starting reconnaissance...")

    # Load subdomains from file
    subdomains = load_subdomains()

    for domain in subdomains:
        print(f"\n[*] Scanning domain: {domain}")

        print("\n[*] Scanning ports...")
        port_range = get_port_range(args.ports, args.custom_ports)
        scan_ports(domain, port_range)

        print("\n[*] Checking for vulnerabilities...")
        shodan_vuln_scan(domain)

    print("\nReconnaissance complete.")
