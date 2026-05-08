#!/usr/bin/env python3
"""
Sample log generator for testing the SIEM dashboard
Generates realistic security events including attacks, normal traffic, and anomalies
"""

import random
import time
import socket
import json
from datetime import datetime


class SampleLogGenerator:
    """Generate sample security logs"""
    
    def __init__(self):
        self.source_ips = [
            "192.168.1.10", "192.168.1.20", "192.168.1.30",
            "10.0.0.5", "10.0.0.15", "172.16.0.100",
            "203.0.113.45", "198.51.100.23", "192.0.2.1"  # External IPs
        ]
        
        self.usernames = ["alice", "bob", "charlie", "admin", "root", "service"]
        self.hostnames = ["web-server-01", "db-server-01", "app-server-01", "firewall-01"]
        
        self.attack_ips = ["203.0.113.45", "198.51.100.23", "192.0.2.1"]
        
    def generate_syslog(self, event_type="normal"):
        """Generate a syslog-format message"""
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        hostname = random.choice(self.hostnames)
        source_ip = random.choice(self.source_ips)
        
        if event_type == "failed_login":
            username = random.choice(self.usernames)
            return f"<38>{timestamp} {hostname} sshd: Failed password for {username} from {source_ip} port 22 ssh2"
        
        elif event_type == "successful_login":
            username = random.choice(self.usernames)
            return f"<38>{timestamp} {hostname} sshd: Accepted password for {username} from {source_ip} port 22 ssh2"
        
        elif event_type == "firewall_block":
            dest_port = random.choice([80, 443, 22, 3389, 8080])
            return f"<134>{timestamp} {hostname} kernel: iptables: BLOCKED IN=eth0 SRC={source_ip} DST=192.168.1.1 PROTO=TCP DPT={dest_port}"
        
        elif event_type == "web_attack":
            attack_patterns = [
                "GET /admin/../../etc/passwd HTTP/1.1",
                "POST /login.php?id=1' OR '1'='1 HTTP/1.1",
                "GET /cgi-bin/test.cgi?exec=/bin/bash HTTP/1.1",
                "GET /wp-admin/admin-ajax.php?action=<script>alert(1)</script> HTTP/1.1"
            ]
            request = random.choice(attack_patterns)
            return f"<38>{timestamp} {hostname} apache: {source_ip} - - [{timestamp}] \"{request}\" 403 -"
        
        elif event_type == "malware":
            malware_names = ["Trojan.Generic", "Backdoor.Agent", "Ransomware.Crypto"]
            malware = random.choice(malware_names)
            return f"<38>{timestamp} {hostname} antivirus: ALERT: {malware} detected in /home/user/downloads/file.exe from {source_ip}"
        
        else:  # normal
            return f"<38>{timestamp} {hostname} systemd: Started User Manager for UID 1000"
    
    def generate_json_log(self, event_type="normal"):
        """Generate a JSON-format log"""
        log = {
            "timestamp": datetime.now().isoformat(),
            "hostname": random.choice(self.hostnames),
            "source_ip": random.choice(self.source_ips),
            "event_type": event_type,
            "severity": "info"
        }
        
        if event_type == "failed_login":
            log.update({
                "user": random.choice(self.usernames),
                "message": "Authentication failed",
                "severity": "medium"
            })
        elif event_type == "intrusion":
            log.update({
                "message": "Intrusion attempt detected",
                "severity": "high",
                "signature_id": random.randint(1000, 9999)
            })
        
        return json.dumps(log)
    
    def simulate_brute_force(self, target_ip="localhost", target_port=5514):
        """Simulate a brute force attack pattern"""
        print("Simulating brute force attack...")
        
        # Multiple failed logins
        for i in range(7):
            log = self.generate_syslog("failed_login")
            self.send_syslog(log, target_ip, target_port)
            time.sleep(0.5)
        
        # Followed by successful login
        time.sleep(1)
        log = self.generate_syslog("successful_login")
        self.send_syslog(log, target_ip, target_port)
        
        print("Brute force simulation complete")
    
    def simulate_port_scan(self, target_ip="localhost", target_port=5514):
        """Simulate port scanning activity"""
        print("Simulating port scan...")
        
        for i in range(25):
            log = self.generate_syslog("firewall_block")
            self.send_syslog(log, target_ip, target_port)
            time.sleep(0.1)
        
        print("Port scan simulation complete")
    
    def simulate_web_attack(self, target_ip="localhost", target_port=5514):
        """Simulate web application attack"""
        print("Simulating web attack...")
        
        for i in range(5):
            log = self.generate_syslog("web_attack")
            self.send_syslog(log, target_ip, target_port)
            time.sleep(0.5)
        
        print("Web attack simulation complete")
    
    def simulate_normal_traffic(self, target_ip="localhost", target_port=5514, count=10):
        """Simulate normal security events"""
        print(f"Simulating {count} normal events...")
        
        event_types = ["normal", "successful_login", "firewall_block"]
        
        for i in range(count):
            event_type = random.choice(event_types)
            log = self.generate_syslog(event_type)
            self.send_syslog(log, target_ip, target_port)
            time.sleep(0.2)
        
        print("Normal traffic simulation complete")
    
    def send_syslog(self, message, host="localhost", port=5514):
        """Send syslog message via UDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode('utf-8'), (host, port))
            sock.close()
            print(f"Sent: {message[:100]}...")
        except Exception as e:
            print(f"Error sending syslog: {e}")
    
    def run_full_simulation(self, target_ip="localhost", target_port=5514):
        """Run a complete simulation with various attack patterns"""
        print("="*60)
        print("Starting Full SIEM Simulation")
        print("="*60)
        
        # Generate normal traffic
        self.simulate_normal_traffic(target_ip, target_port, 20)
        time.sleep(2)
        
        # Simulate brute force attack
        self.simulate_brute_force(target_ip, target_port)
        time.sleep(2)
        
        # More normal traffic
        self.simulate_normal_traffic(target_ip, target_port, 10)
        time.sleep(2)
        
        # Simulate port scan
        self.simulate_port_scan(target_ip, target_port)
        time.sleep(2)
        
        # Simulate web attacks
        self.simulate_web_attack(target_ip, target_port)
        time.sleep(2)
        
        # Final normal traffic
        self.simulate_normal_traffic(target_ip, target_port, 15)
        
        print("="*60)
        print("Simulation Complete!")
        print("="*60)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate sample security logs for SIEM testing")
    parser.add_argument("--host", default="localhost", help="Syslog server host")
    parser.add_argument("--port", type=int, default=5514, help="Syslog server port")
    parser.add_argument("--mode", choices=["full", "brute-force", "port-scan", "web-attack", "normal"],
                       default="full", help="Simulation mode")
    parser.add_argument("--count", type=int, default=20, help="Number of events for normal mode")
    
    args = parser.parse_args()
    
    generator = SampleLogGenerator()
    
    if args.mode == "full":
        generator.run_full_simulation(args.host, args.port)
    elif args.mode == "brute-force":
        generator.simulate_brute_force(args.host, args.port)
    elif args.mode == "port-scan":
        generator.simulate_port_scan(args.host, args.port)
    elif args.mode == "web-attack":
        generator.simulate_web_attack(args.host, args.port)
    elif args.mode == "normal":
        generator.simulate_normal_traffic(args.host, args.port, args.count)
