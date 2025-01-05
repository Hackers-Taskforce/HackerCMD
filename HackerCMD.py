import argparse
import hashlib
import socket
import subprocess
import whois
import dns.resolver
import requests
import ssl
from ipwhois import IPWhois
from urllib.parse import urlparse
from shodan import Shodan
import nmap
import ftplib
import smtplib
import re
from colorama import Fore, Back, Style, init
import base64

# Initialize colorama
init(autoreset=True)

# Function to display the banner
def display_banner():
    banner = f"""
{Fore.GREEN + Style.BRIGHT}
██████╗ ███████╗██╗  ██╗██╗   ██╗███████╗██╗  ██╗███████╗███████╗
██╔══██╗██╔════╝██║  ██║██║   ██║██╔════╝██║  ██║██╔════╝██╔════╝
██████╔╝█████╗  ███████║██║   ██║█████╗  ███████║█████╗  █████╗  
██╔═══╝ ██╔══╝  ██╔══██║██║   ██║██╔══╝  ██╔══██║██╔══╝  ██╔══╝  
██║     ███████╗██║  ██║╚██████╔╝███████╗██║  ██║███████╗███████╗
╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝

{Fore.CYAN}Created by: {Fore.YELLOW}ChickenWithACrown (Hackers Taskforce)
{Fore.CYAN}Version: {Fore.YELLOW}7.5.98
{Fore.GREEN + Style.BRIGHT}---------------------------------------------

"""
    print(banner)

# Function Definitions

def scan_ip(ip, ports):
    nm = nmap.PortScanner()
    print(f"Scanning IP: {ip} for ports: {ports}")
    nm.scan(ip, ','.join(map(str, ports)))
    for port in ports:
        if nm[ip].has_tcp(port):
            state = nm[ip].tcp(port)['state']
            print(f"Port {port} is {state}")
        else:
            print(f"Port {port} is closed")

def generate_hash(data, algorithm):
    hash_obj = hashlib.new(algorithm, data.encode())
    return hash_obj.hexdigest()

def crack_hash(hash_to_crack, wordlist):
    for word in wordlist:
        if generate_hash(word, 'sha256') == hash_to_crack:
            print(f"Found match! The original value is: {word}")
            return word
    print("No match found.")
    return None

def password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char.islower() for char in password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    return score

def dns_lookup(domain):
    result = dns.resolver.resolve(domain, 'A')
    return [ip.address for ip in result]

def reverse_dns(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except socket.herror:
        return "No PTR record found"

def ping_ip(ip):
    response = subprocess.run(['ping', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return response.stdout.decode()

def traceroute(target):
    response = subprocess.run(['traceroute', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return response.stdout.decode()

def whois_lookup(target):
    result = whois.whois(target)
    return result

def ip_geolocation(ip):
    response = requests.get(f'https://ipinfo.io/{ip}/json')
    return response.json()

def network_info():
    response = subprocess.run(['ipconfig'], stdout=subprocess.PIPE)
    return response.stdout.decode()

def get_http_headers(url):
    response = requests.head(url)
    return response.headers

def ssl_certificate_info(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            return cert

def shodan_search(api_key, query):
    api = Shodan(api_key)
    results = api.search(query)
    return results

def dns_brute_force(domain, wordlist):
    subdomains = []
    for word in wordlist:
        try:
            dns.resolver.resolve(f'{word}.{domain}', 'A')
            subdomains.append(word)
        except dns.resolver.NXDOMAIN:
            continue
    return subdomains

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')  # Scan ports 1 to 1024
    return nm[target].all_tcp()

def ftp_banner_grab(ip):
    try:
        ftp = ftplib.FTP(ip)
        ftp.connect(ip, 21, timeout=2)
        ftp.sendcmd('HELLO')
        banner = ftp.getwelcome()
        ftp.quit()
        return banner
    except Exception as e:
        return str(e)

def smtp_banner_grab(ip):
    try:
        smtp = smtplib.SMTP(ip)
        banner = smtp.docmd('EHLO')
        smtp.quit()
        return banner
    except Exception as e:
        return str(e)

def xss_vulnerability_scan(url):
    response = requests.get(url)
    xss_pattern = r"<script.*?>.*?</script.*?>"
    matches = re.findall(xss_pattern, response.text, re.IGNORECASE)
    return matches

def sql_injection_scan(url):
    payloads = ["' OR 1=1 --", '" OR 1=1 --', "'; DROP TABLE users --"]
    vulnerable = []
    for payload in payloads:
        test_url = url + payload
        response = requests.get(test_url)
        if "error" in response.text or "mysql" in response.text:
            vulnerable.append(test_url)
    return vulnerable

# Base64 Encode and Decode Functions
def encode_base64(data):
    encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
    return encoded_data

def decode_base64(encoded_data):
    decoded_data = base64.b64decode(encoded_data).decode('utf-8')
    return decoded_data

# Argument Parsing Setup
def main():
    # Display the banner at the start
    display_banner()
    
    # Argument parser setup
    parser = argparse.ArgumentParser(description="HackerCMD - Multi-purpose Command-Line Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # IP Scanner
    ip_parser = subparsers.add_parser("scan", help="Scan IP for open ports")
    ip_parser.add_argument("ip", help="IP address to scan")
    ip_parser.add_argument("--ports", nargs="+", type=int, default=[80, 443, 22, 21], help="Ports to scan")

    # Hash Generator
    hash_parser = subparsers.add_parser("hash", help="Generate a hash")
    hash_parser.add_argument("data", help="Data to hash")
    hash_parser.add_argument("--algorithm", choices=hashlib.algorithms_available, default="sha256", help="Hashing algorithm")

    # Hash Cracking
    hash_crack_parser = subparsers.add_parser("crack", help="Attempt to crack a SHA256 hash")
    hash_crack_parser.add_argument("hash_to_crack", help="The SHA256 hash to crack")
    hash_crack_parser.add_argument("wordlist", help="Path to wordlist file for brute-forcing")

    # Password Strength
    password_parser = subparsers.add_parser("password", help="Check password strength")
    password_parser.add_argument("password", help="Password to check")

    # DNS Lookup
    dns_parser = subparsers.add_parser("dns", help="Get DNS records for a domain")
    dns_parser.add_argument("domain", help="Domain to look up")

    # Reverse DNS
    reverse_parser = subparsers.add_parser("reverse", help="Perform a reverse DNS lookup")
    reverse_parser.add_argument("ip", help="IP address to resolve")

    # Ping
    ping_parser = subparsers.add_parser("ping", help="Ping an IP address")
    ping_parser.add_argument("ip", help="IP address to ping")

    # Traceroute
    traceroute_parser = subparsers.add_parser("traceroute", help="Perform a traceroute")
    traceroute_parser.add_argument("target", help="IP address or domain to trace")

    # WHOIS
    whois_parser = subparsers.add_parser("whois", help="Perform a WHOIS lookup on an IP or domain")
    whois_parser.add_argument("target", help="IP address or domain to look up")

    # IP Geolocation
    geo_parser = subparsers.add_parser("geolocation", help="Get geolocation information for an IP address")
    geo_parser.add_argument("ip", help="IP address to geolocate")

    # Network Info
    net_parser = subparsers.add_parser("network", help="Retrieve local network information")

    # HTTP Headers
    headers_parser = subparsers.add_parser("headers", help="Get HTTP response headers")
    headers_parser.add_argument("url", help="URL to get headers from")

    # SSL Certificate Info
    ssl_parser = subparsers.add_parser("ssl", help="Get SSL certificate information")
    ssl_parser.add_argument("domain", help="Domain to retrieve SSL info from")

    # Shodan Search
    shodan_parser = subparsers.add_parser("shodan", help="Search Shodan for connected devices/services")
    shodan_parser.add_argument("api_key", help="Shodan API key")
    shodan_parser.add_argument("query", help="Search query for Shodan")

    # DNS Brute Force
    brute_parser = subparsers.add_parser("dns_brute", help="Brute-force DNS subdomains")
    brute_parser.add_argument("domain", help="Domain to brute-force subdomains")
    brute_parser.add_argument("wordlist", help="Wordlist file for subdomains")

    # Nmap Scan
    nmap_parser = subparsers.add_parser("nmap", help="Run Nmap scan on a target")
    nmap_parser.add_argument("target", help="Target to scan with Nmap")

    # FTP Banner Grab
    ftp_parser = subparsers.add_parser("ftp_banner", help="Grab FTP banner from IP address")
    ftp_parser.add_argument("ip", help="IP address to grab FTP banner from")

    # SMTP Banner Grab
    smtp_parser = subparsers.add_parser("smtp_banner", help="Grab SMTP banner from IP address")
    smtp_parser.add_argument("ip", help="IP address to grab SMTP banner from")

    # XSS Vulnerability Scan
    xss_parser = subparsers.add_parser("xss_scan", help="Scan a website for XSS vulnerabilities")
    xss_parser.add_argument("url", help="URL to scan for XSS vulnerabilities")

    # SQL Injection Scan
    sql_parser = subparsers.add_parser("sql_scan", help="Scan a website for SQL Injection vulnerabilities")
    sql_parser.add_argument("url", help="URL to scan for SQL injection")

    # Base64 Encoding/Decoding
    base64_parser = subparsers.add_parser("base64", help="Base64 encode or decode data")
    base64_parser.add_argument("action", choices=["encode", "decode"], help="Action to perform")
    base64_parser.add_argument("data", help="Data to encode or decode")

    args = parser.parse_args()

    try:
        if args.command == "scan":
            scan_ip(args.ip, args.ports)
        elif args.command == "hash":
            print(f"Hash ({args.algorithm}): {generate_hash(args.data, args.algorithm)}")
        elif args.command == "crack":
            with open(args.wordlist, 'r') as f:
                wordlist = f.read().splitlines()
            crack_hash(args.hash_to_crack, wordlist)
        elif args.command == "password":
            print(f"Password Strength: {password_strength(args.password)}/5")
        elif args.command == "dns":
            dns_records = dns_lookup(args.domain)
            print(f"DNS Records for {args.domain}: {dns_records}")
        elif args.command == "reverse":
            print(f"Reverse DNS for {args.ip}: {reverse_dns(args.ip)}")
        elif args.command == "ping":
            print(ping_ip(args.ip))
        elif args.command == "traceroute":
            print(traceroute(args.target))
        elif args.command == "whois":
            print(whois_lookup(args.target))
        elif args.command == "geolocation":
            print(ip_geolocation(args.ip))
        elif args.command == "network":
            print(network_info())
        elif args.command == "headers":
            print(get_http_headers(args.url))
        elif args.command == "ssl":
            print(ssl_certificate_info(args.domain))
        elif args.command == "shodan":
            print(shodan_search(args.api_key, args.query))
        elif args.command == "dns_brute":
            with open(args.wordlist, 'r') as f:
                wordlist = f.read().splitlines()
            subdomains = dns_brute_force(args.domain, wordlist)
            print(f"Found subdomains: {subdomains}")
        elif args.command == "nmap":
            print(nmap_scan(args.target))
        elif args.command == "ftp_banner":
            print(ftp_banner_grab(args.ip))
        elif args.command == "smtp_banner":
            print(smtp_banner_grab(args.ip))
        elif args.command == "xss_scan":
            print(xss_vulnerability_scan(args.url))
        elif args.command == "sql_scan":
            print(sql_injection_scan(args.url))
        elif args.command == "base64":
            if args.action == "encode":
                print(f"Base64 Encoded: {encode_base64(args.data)}")
            elif args.action == "decode":
                print(f"Base64 Decoded: {decode_base64(args.data)}")
    except Exception as e:
        print(f"Error: {e}")
        

if __name__ == "__main__":
    main()
