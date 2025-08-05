import socket
import threading
import requests
import subprocess
import time
import itertools
from concurrent.futures import ThreadPoolExecutor
import paramiko
import ftplib
import argparse
import sys

class PenetrationTestingToolkit:
    def __init__(self):
        self.results = []
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        
    def port_scanner(self, target, ports=None, threads=100):
        """Advanced port scanner with threading"""
        print(f"Starting port scan on {target}")
        print("-" * 40)
        
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        banner = sock.recv(1024).decode().strip()
                    except:
                        banner = ""
                    open_ports.append((port, banner))
                    print(f"Port {port}: OPEN {banner[:50]}")
                sock.close()
            except Exception as e:
                pass
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(scan_port, ports)
        
        print(f"\nFound {len(open_ports)} open ports")
        return open_ports
    
    def service_detector(self, target, port):
        """Detect service running on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target)
                sock.send(request.encode())
            
            banner = sock.recv(1024).decode().strip()
            sock.close()
            
            # Identify common services
            if "SSH" in banner:
                return "SSH"
            elif "FTP" in banner:
                return "FTP"
            elif "HTTP" in banner or "Server:" in banner:
                return "HTTP"
            elif "SMTP" in banner:
                return "SMTP"
            elif "MySQL" in banner:
                return "MySQL"
            else:
                return f"Unknown ({banner[:20]})"
                
        except Exception as e:
            return "Unknown"
    
    def brute_force_ssh(self, target, port=22, usernames=None, passwords=None):
        """SSH brute force attack"""
        print(f"Starting SSH brute force on {target}:{port}")
        
        if usernames is None:
            usernames = ['admin', 'root', 'user', 'test', 'guest']
        if passwords is None:
            passwords = ['admin', 'password', '123456', 'root', 'test', '']
        
        successful_logins = []
        
        for username in usernames:
            for password in passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target, port=port, username=username, password=password, timeout=5)
                    
                    successful_logins.append((username, password))
                    print(f"✓ SSH Login successful: {username}:{password}")
                    ssh.close()
                    
                except paramiko.AuthenticationException:
                    print(f"✗ Failed: {username}:{password}")
                except Exception as e:
                    print(f"Error: {e}")
                    continue
                
                time.sleep(0.5)  # Avoid detection
        
        return successful_logins
    
    def brute_force_ftp(self, target, port=21, usernames=None, passwords=None):
        """FTP brute force attack"""
        print(f"Starting FTP brute force on {target}:{port}")
        
        if usernames is None:
            usernames = ['admin', 'ftp', 'user', 'test', 'anonymous']
        if passwords is None:
            passwords = ['admin', 'password', 'ftp', '', 'anonymous']
        
        successful_logins = []
        
        for username in usernames:
            for password in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=5)
                    ftp.login(username, password)
                    
                    successful_logins.append((username, password))
                    print(f"✓ FTP Login successful: {username}:{password}")
                    ftp.quit()
                    
                except ftplib.error_perm:
                    print(f"✗ Failed: {username}:{password}")
                except Exception as e:
                    continue
                
                time.sleep(0.5)
        
        return successful_logins
    
    def web_directory_scanner(self, target_url, wordlist=None):
        """Web directory and file scanner"""
        print(f"Starting directory scan on {target_url}")
        
        if wordlist is None:
            wordlist = [
                'admin', 'login', 'backup', 'config', 'test', 'temp',
                'uploads', 'images', 'css', 'js', 'api', 'private',
                'phpmyadmin', 'wp-admin', 'administrator', 'panel'
            ]
        
        found_directories = []
        
        for directory in wordlist:
            url = f"{target_url.rstrip('/')}/{directory}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    found_directories.append((url, response.status_code))
                    print(f"✓ Found: {url} (Status: {response.status_code})")
                elif response.status_code == 403:
                    found_directories.append((url, response.status_code))
                    print(f"⚠ Forbidden: {url} (Status: {response.status_code})")
            except Exception as e:
                continue
        
        return found_directories
    
    def vulnerability_scanner(self, target):
        """Basic vulnerability scanner"""
        print(f"Starting vulnerability scan on {target}")
        vulnerabilities = []
        
        # Check for common vulnerabilities
        try:
            # Check for open SMB shares
            response = subprocess.run(['nmap', '-p', '445', '--script', 'smb-enum-shares', target], 
                                    capture_output=True, text=True, timeout=30)
            if 'Anonymous access allowed' in response.stdout:
                vulnerabilities.append("Anonymous SMB access allowed")
                print("✗ Anonymous SMB access detected")
        except:
            pass
        
        # Check for weak SSL/TLS
        try:
            response = requests.get(f"https://{target}", verify=False, timeout=10)
            if 'Server' in response.headers:
                server = response.headers['Server']
                if any(weak in server.lower() for weak in ['apache/2.2', 'nginx/1.0', 'iis/6.0']):
                    vulnerabilities.append(f"Outdated web server: {server}")
                    print(f"✗ Outdated web server detected: {server}")
        except:
            pass
        
        return vulnerabilities
    
    def network_discovery(self, network_range):
        """Discover active hosts in network range"""
        print(f"Discovering hosts in {network_range}")
        active_hosts = []
        
        # Extract network base (e.g., 192.168.1 from 192.168.1.0/24)
        base_ip = '.'.join(network_range.split('.')[:-1])
        
        def ping_host(ip):
            try:
                response = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                        capture_output=True, timeout=5)
                if response.returncode == 0:
                    active_hosts.append(ip)
                    print(f"✓ Host alive: {ip}")
            except:
                pass
        
        # Scan range 1-254
        with ThreadPoolExecutor(max_workers=50) as executor:
            ips = [f"{base_ip}.{i}" for i in range(1, 255)]
            executor.map(ping_host, ips)
        
        print(f"Found {len(active_hosts)} active hosts")
        return active_hosts
    
    def generate_report(self, results):
        """Generate penetration testing report"""
        print("\n" + "=" * 60)
        print("PENETRATION TESTING REPORT")
        print("=" * 60)
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"Report generated: {timestamp}")
        print()
        
        for category, data in results.items():
            print(f"{category.upper()}:")
            print("-" * 40)
            
            if isinstance(data, list):
                for item in data:
                    print(f"  {item}")
            else:
                print(f"  {data}")
            print()

def main():
    toolkit = PenetrationTestingToolkit()
    
    while True:
        print("\n=== Penetration Testing Toolkit ===")
        print("1. Port Scanner")
        print("2. Service Detection")
        print("3. SSH Brute Force")
        print("4. FTP Brute Force")
        print("5. Web Directory Scanner")
        print("6. Vulnerability Scanner")
        print("7. Network Discovery")
        print("8. Full Scan (All modules)")
        print("9. Exit")
        
        choice = input("Select option (1-9): ").strip()
        
        if choice == '1':
            target = input("Enter target IP/hostname: ").strip()
            ports_input = input("Enter ports (comma-separated) or press Enter for common ports: ").strip()
            
            if ports_input:
                ports = [int(p.strip()) for p in ports_input.split(',')]
            else:
                ports = None
            
            results = toolkit.port_scanner(target, ports)
        
        elif choice == '2':
            target = input("Enter target IP/hostname: ").strip()
            port = int(input("Enter port: ").strip())
            service = toolkit.service_detector(target, port)
            print(f"Service on port {port}: {service}")
        
        elif choice == '3':
            target = input("Enter target IP/hostname: ").strip()
            port = int(input("Enter SSH port (default 22): ").strip() or "22")
            results = toolkit.brute_force_ssh(target, port)
        
        elif choice == '4':
            target = input("Enter target IP/hostname: ").strip()
            port = int(input("Enter FTP port (default 21): ").strip() or "21")
            results = toolkit.brute_force_ftp(target, port)
        
        elif choice == '5':
            target_url = input("Enter target URL: ").strip()
            results = toolkit.web_directory_scanner(target_url)
        
        elif choice == '6':
            target = input("Enter target IP/hostname: ").strip()
            results = toolkit.vulnerability_scanner(target)
        
        elif choice == '7':
            network = input("Enter network range (e.g., 192.168.1.0/24): ").strip()
            results = toolkit.network_discovery(network)
        
        elif choice == '8':
            target = input("Enter target IP/hostname: ").strip()
            print("Performing comprehensive scan...")
            
            all_results = {}
            all_results['Port Scan'] = toolkit.port_scanner(target)
            all_results['Vulnerabilities'] = toolkit.vulnerability_scanner(target)
            
            # Check if web server is running
            if any(port[0] in [80, 443, 8080] for port in all_results['Port Scan']):
                protocol = 'https' if any(port[0] in [443, 8443] for port in all_results['Port Scan']) else 'http'
                target_url = f"{protocol}://{target}"
                all_results['Web Directories'] = toolkit.web_directory_scanner(target_url)
            
            toolkit.generate_report(all_results)
        
        elif choice == '9':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
