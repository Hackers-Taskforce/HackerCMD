# HackerCMD - Multi-purpose Command-Line Tool

HackerCMD is a multi-functional command-line tool designed for ethical hackers, penetration testers, and cybersecurity enthusiasts. It supports a variety of features like network scanning, vulnerability scanning, DNS lookups, SSL certificate retrieval, banner grabbing, brute-forcing subdomains, password strength checking, and more.

#(Creator Note:)
If you fine and issue with the code feel free to reach out via discord or with the org on GitHub..
--
## Features

- IP scanning
- Hash generation (supports multiple hashing algorithms)
- Password strength checking
- DNS lookups and reverse DNS
- Ping and traceroute tools
- WHOIS information retrieval
- Geolocation lookup for IP addresses
- Network information retrieval
- HTTP header fetching
- SSL certificate information
- Shodan search integration
- DNS brute-forcing subdomains
- Nmap port scanning
- FTP and SMTP banner grabbing
- Vulnerability scanning (XSS, SQL injection)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Hackers-Taskforce/HackerCMD.git
   cd HackerCMD
   ```
## Installation

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Syntax
```bash
python hackercmd.py [command] [options]
```

### Commands

1. **scan** - Scan IP for open ports
   - **Usage**:
     ```bash
     python hackercmd.py scan [IP] --ports [port1] [port2] ...
     ```
   - **Description**: Scan a target IP for open ports.
   - **Example**:
     ```bash
     python hackercmd.py scan 192.168.1.1 --ports 80 443 22
     ```

2. **hash** - Generate a hash of the provided data
   - **Usage**:
     ```bash
     python hackercmd.py hash [data] --algorithm [hash_algorithm]
     ```
   - **Description**: Generate a hash from the given data using a specified algorithm (default is SHA256).
   - **Example**:
     ```bash
     python hackercmd.py hash "hello world" --algorithm sha256
     ```

3. **password** - Check password strength
   - **Usage**:
     ```bash
     python hackercmd.py password [password]
     ```
   - **Description**: Check the strength of a password (returns a score from 1 to 5).
   - **Example**:
     ```bash
     python hackercmd.py password "StrongPass123!"
     ```

4. **dns** - DNS lookup for a domain
   - **Usage**:
     ```bash
     python hackercmd.py dns [domain]
     ```
   - **Description**: Get DNS 'A' records for a domain.
   - **Example**:
     ```bash
     python hackercmd.py dns example.com
     ```

5. **reverse** - Reverse DNS lookup
   - **Usage**:
     ```bash
     python hackercmd.py reverse [IP]
     ```
   - **Description**: Perform a reverse DNS lookup on an IP address.
   - **Example**:
     ```bash
     python hackercmd.py reverse 8.8.8.8
     ```

6. **ping** - Ping an IP address
   - **Usage**:
     ```bash
     python hackercmd.py ping [IP]
     ```
   - **Description**: Ping an IP address to check its reachability.
   - **Example**:
     ```bash
     python hackercmd.py ping 192.168.1.1
     ```

7. **traceroute** - Perform a traceroute to a target
   - **Usage**:
     ```bash
     python hackercmd.py traceroute [target]
     ```
   - **Description**: Perform a traceroute to an IP or domain.
   - **Example**:
     ```bash
     python hackercmd.py traceroute example.com
     ```

8. **whois** - WHOIS lookup for a domain or IP
   - **Usage**:
     ```bash
     python hackercmd.py whois [domain_or_IP]
     ```
   - **Description**: Retrieve WHOIS information for a domain or IP.
   - **Example**:
     ```bash
     python hackercmd.py whois example.com
     ```

9. **geolocation** - Get geolocation information for an IP address
   - **Usage**:
     ```bash
     python hackercmd.py geolocation [IP]
     ```
   - **Description**: Retrieve geolocation information for an IP address.
   - **Example**:
     ```bash
     python hackercmd.py geolocation 8.8.8.8
     ```

10. **network** - Retrieve local network information
    - **Usage**:
      ```bash
      python hackercmd.py network
      ```
    - **Description**: Display local network information such as IP configuration.
    - **Example**:
      ```bash
      python hackercmd.py network
      ```

11. **headers** - Fetch HTTP headers from a URL
    - **Usage**:
      ```bash
      python hackercmd.py headers [URL]
      ```
    - **Description**: Retrieve HTTP response headers for a specified URL.
    - **Example**:
      ```bash
      python hackercmd.py headers http://example.com
      ```

12. **ssl** - Retrieve SSL certificate information for a domain
    - **Usage**:
      ```bash
      python hackercmd.py ssl [domain]
      ```
    - **Description**: Retrieve SSL certificate details for a domain.
    - **Example**:
      ```bash
      python hackercmd.py ssl example.com
      ```

13. **shodan** - Search Shodan for devices or services
    - **Usage**:
      ```bash
      python hackercmd.py shodan [API_KEY] [query]
      ```
    - **Description**: Use Shodan API to search for devices or services based on a query.
    - **Example**:
      ```bash
      python hackercmd.py shodan YOUR_API_KEY apache
      ```

14. **dns_brute** - Brute-force DNS subdomains using a wordlist
    - **Usage**:
      ```bash
      python hackercmd.py dns_brute [domain] [wordlist]
      ```
    - **Description**: Brute-force subdomains for a domain using a wordlist.
    - **Example**:
      ```bash
      python hackercmd.py dns_brute example.com wordlist.txt
      ```

15. **nmap** - Run an Nmap scan on a target
    - **Usage**:
      ```bash
      python hackercmd.py nmap [target]
      ```
    - **Description**: Perform an Nmap port scan on the given target (scans ports 1-1024).
    - **Example**:
      ```bash
      python hackercmd.py nmap 192.168.1.1
      ```

16. **ftp_banner** - Grab FTP banner from an IP address
    - **Usage**:
      ```bash
      python hackercmd.py ftp_banner [IP]
      ```
    - **Description**: Grab the FTP banner from a given IP address.
    - **Example**:
      ```bash
      python hackercmd.py ftp_banner 192.168.1.1
      ```

17. **smtp_banner** - Grab SMTP banner from an IP address
    - **Usage**:
      ```bash
      python hackercmd.py smtp_banner [IP]
      ```
    - **Description**: Grab the SMTP banner from a given IP address.
    - **Example**:
      ```bash
      python hackercmd.py smtp_banner 192.168.1.1
      ```

18. **xss_scan** - Scan a website for XSS vulnerabilities
    - **Usage**:
      ```bash
      python hackercmd.py xss_scan [URL]
      ```
    - **Description**: Scan a website for potential XSS vulnerabilities.
    - **Example**:
      ```bash
      python hackercmd.py xss_scan http://example.com
      ```

19. **sql_scan** - Scan a website for SQL Injection vulnerabilities
    - **Usage**:
      ```bash
      python hackercmd.py sql_scan [URL]
      ```
    - **Description**: Scan a website for potential SQL injection vulnerabilities.
    - **Example**:
      ```bash
      python hackercmd.py sql_scan http://example.com
      ```

## Requirements

- Python 3.x
- Dependencies listed in requirements.txt
```bash
requests
nmap
shodan
ftplib
smtplib
python-whois
dnsresolver
ipwhois
colorama
```

## Disclaimer

This tool is intended for ethical use only. Use it responsibly and ensure you have permission before scanning or interacting with any target. Unauthorized access or attacks on networks and systems are illegal and unethical.
