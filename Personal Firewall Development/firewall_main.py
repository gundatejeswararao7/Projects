#!/usr/bin/env python3
"""
Personal Firewall Backend
A lightweight firewall implementation with threat intelligence integration
"""

import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import requests
import sqlite3
import hashlib

class ThreatIntelligence:
    """Integrate with threat intelligence feeds"""
    
    def __init__(self, db_path='firewall.db'):
        self.db_path = db_path
        self.malicious_ips = set()
        self.cache_duration = 3600  # 1 hour
        self.last_update = 0
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for logging"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                reason TEXT,
                packet_hash TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS allowed_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                ip TEXT PRIMARY KEY,
                threat_level TEXT,
                last_seen TEXT,
                source TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def update_threat_feeds(self):
        """Update threat intelligence from public sources"""
        current_time = time.time()
        
        if current_time - self.last_update < self.cache_duration:
            return
            
        logging.info("Updating threat intelligence feeds...")
        
        # AbuseIPDB API (Free tier available)
        # Note: Users should register for their own API key at https://www.abuseipdb.com/api
        try:
            # Feodo Tracker - Botnet C&C IPs (Free, no API key needed)
            response = requests.get(
                'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                timeout=10
            )
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.malicious_ips.add(line)
                        self.log_threat_intel(line, 'high', 'Feodo Tracker')
                        
            logging.info(f"Loaded {len(self.malicious_ips)} malicious IPs from threat feeds")
            
        except Exception as e:
            logging.error(f"Error updating threat feeds: {e}")
            
        self.last_update = current_time
        
    def log_threat_intel(self, ip, threat_level, source):
        """Log threat intelligence data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO threat_intel (ip, threat_level, last_seen, source)
                VALUES (?, ?, ?, ?)
            ''', (ip, threat_level, datetime.now().isoformat(), source))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Error logging threat intel: {e}")
            
    def is_malicious(self, ip):
        """Check if IP is in threat intelligence database"""
        return ip in self.malicious_ips


class FirewallRuleEngine:
    """Rule engine for packet filtering"""
    
    def __init__(self, rules_file='firewall_rules.json'):
        self.rules_file = rules_file
        self.rules = self.load_rules()
        self.connection_tracker = defaultdict(lambda: {'count': 0, 'last_seen': 0})
        
    def load_rules(self):
        """Load firewall rules from JSON file"""
        default_rules = {
            "default_policy": "allow",
            "rules": [
                {
                    "name": "Block common attack ports",
                    "action": "block",
                    "dst_ports": [23, 135, 139, 445, 3389],
                    "protocol": "tcp",
                    "enabled": True
                },
                {
                    "name": "Allow SSH",
                    "action": "allow",
                    "dst_ports": [22],
                    "protocol": "tcp",
                    "enabled": True
                },
                {
                    "name": "Allow HTTP/HTTPS",
                    "action": "allow",
                    "dst_ports": [80, 443],
                    "protocol": "tcp",
                    "enabled": True
                },
                {
                    "name": "Allow DNS",
                    "action": "allow",
                    "dst_ports": [53],
                    "protocol": "udp",
                    "enabled": True
                },
                {
                    "name": "Rate limit - SYN flood protection",
                    "action": "rate_limit",
                    "max_connections": 100,
                    "time_window": 10,
                    "enabled": True
                }
            ],
            "blacklist_ips": [],
            "whitelist_ips": ["127.0.0.1", "::1"]
        }
        
        if Path(self.rules_file).exists():
            try:
                with open(self.rules_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading rules: {e}")
                return default_rules
        else:
            # Create default rules file
            with open(self.rules_file, 'w') as f:
                json.dump(default_rules, f, indent=2)
            return default_rules
            
    def reload_rules(self):
        """Reload rules from file"""
        self.rules = self.load_rules()
        logging.info("Firewall rules reloaded")
        
    def check_rate_limit(self, src_ip):
        """Check if source IP exceeds rate limit"""
        current_time = time.time()
        tracker = self.connection_tracker[src_ip]
        
        # Reset counter if time window expired
        if current_time - tracker['last_seen'] > 10:
            tracker['count'] = 0
            
        tracker['count'] += 1
        tracker['last_seen'] = current_time
        
        # Find rate limit rule
        for rule in self.rules.get('rules', []):
            if rule.get('action') == 'rate_limit' and rule.get('enabled'):
                if tracker['count'] > rule.get('max_connections', 100):
                    return False
                    
        return True
        
    def evaluate_packet(self, packet, threat_intel):
        """Evaluate packet against firewall rules"""
        if not packet.haslayer(IP):
            return True, "No IP layer"
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = None
        src_port = None
        dst_port = None
        
        # Extract protocol and ports
        if packet.haslayer(TCP):
            protocol = 'tcp'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = 'udp'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = 'icmp'
            
        # Check whitelist
        if src_ip in self.rules.get('whitelist_ips', []):
            return True, "Whitelisted IP"
            
        # Check blacklist
        if src_ip in self.rules.get('blacklist_ips', []):
            return False, "Blacklisted IP"
            
        # Check threat intelligence
        if threat_intel.is_malicious(src_ip):
            return False, "Malicious IP (Threat Intel)"
            
        # Check rate limiting
        if not self.check_rate_limit(src_ip):
            return False, "Rate limit exceeded"
            
        # Evaluate rules
        for rule in self.rules.get('rules', []):
            if not rule.get('enabled', True):
                continue
                
            # Check protocol match
            if 'protocol' in rule and protocol != rule['protocol']:
                continue
                
            # Check port match
            if 'dst_ports' in rule and dst_port:
                if dst_port in rule['dst_ports']:
                    if rule['action'] == 'block':
                        return False, f"Blocked by rule: {rule['name']}"
                    elif rule['action'] == 'allow':
                        return True, f"Allowed by rule: {rule['name']}"
                        
        # Default policy
        default_policy = self.rules.get('default_policy', 'allow')
        if default_policy == 'block':
            return False, "Default policy: block"
        else:
            return True, "Default policy: allow"


class PersonalFirewall:
    """Main firewall application"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.running = False
        self.threat_intel = ThreatIntelligence()
        self.rule_engine = FirewallRuleEngine()
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'packets_allowed': 0
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('firewall.log'),
                logging.StreamHandler()
            ]
        )
        
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        try:
            self.stats['packets_processed'] += 1
            
            # Evaluate packet
            allowed, reason = self.rule_engine.evaluate_packet(packet, self.threat_intel)
            
            if allowed:
                self.stats['packets_allowed'] += 1
                self.log_allowed_packet(packet)
            else:
                self.stats['packets_blocked'] += 1
                self.log_blocked_packet(packet, reason)
                logging.warning(f"BLOCKED: {self.get_packet_summary(packet)} - {reason}")
                
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            
    def get_packet_summary(self, packet):
        """Get human-readable packet summary"""
        if not packet.haslayer(IP):
            return "Non-IP packet"
            
        summary = f"{packet[IP].src}"
        
        if packet.haslayer(TCP):
            summary += f":{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} (TCP)"
        elif packet.haslayer(UDP):
            summary += f":{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport} (UDP)"
        elif packet.haslayer(ICMP):
            summary += f" -> {packet[IP].dst} (ICMP)"
        else:
            summary += f" -> {packet[IP].dst}"
            
        return summary
        
    def log_blocked_packet(self, packet, reason):
        """Log blocked packet to database"""
        try:
            if not packet.haslayer(IP):
                return
                
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = None
            dst_port = None
            protocol = 'other'
            
            if packet.haslayer(TCP):
                protocol = 'tcp'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = 'udp'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = 'icmp'
                
            # Create packet hash for deduplication
            packet_hash = hashlib.md5(
                f"{src_ip}{dst_ip}{src_port}{dst_port}{protocol}".encode()
            ).hexdigest()
            
            conn = sqlite3.connect(self.threat_intel.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO blocked_packets 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, reason, packet_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                src_ip, dst_ip, src_port, dst_port, protocol, reason, packet_hash
            ))
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Error logging blocked packet: {e}")
            
    def log_allowed_packet(self, packet):
        """Log allowed packet to database (sampling to avoid overhead)"""
        try:
            # Only log 1% of allowed packets to reduce overhead
            import random
            if random.random() > 0.01:
                return
                
            if not packet.haslayer(IP):
                return
                
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = None
            dst_port = None
            protocol = 'other'
            
            if packet.haslayer(TCP):
                protocol = 'tcp'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = 'udp'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = 'icmp'
                
            conn = sqlite3.connect(self.threat_intel.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO allowed_packets 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                src_ip, dst_ip, src_port, dst_port, protocol
            ))
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Error logging allowed packet: {e}")
            
    def update_threat_feeds_periodically(self):
        """Update threat intelligence feeds periodically"""
        while self.running:
            self.threat_intel.update_threat_feeds()
            time.sleep(3600)  # Update every hour
            
    def print_stats(self):
        """Print firewall statistics periodically"""
        while self.running:
            time.sleep(30)  # Print stats every 30 seconds
            logging.info(f"Stats - Processed: {self.stats['packets_processed']}, "
                        f"Allowed: {self.stats['packets_allowed']}, "
                        f"Blocked: {self.stats['packets_blocked']}")
            
    def start(self):
        """Start the firewall"""
        logging.info("Starting Personal Firewall...")
        logging.info(f"Interface: {self.interface or 'all'}")
        
        self.running = True
        
        # Start threat intelligence update thread
        threat_thread = threading.Thread(target=self.update_threat_feeds_periodically)
        threat_thread.daemon = True
        threat_thread.start()
        
        # Start stats printing thread
        stats_thread = threading.Thread(target=self.print_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        # Initial threat feed update
        self.threat_intel.update_threat_feeds()
        
        logging.info("Firewall is now active. Press Ctrl+C to stop.")
        
        try:
            # Start packet sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False
            )
        except KeyboardInterrupt:
            logging.info("\nShutting down firewall...")
            self.running = False
        except Exception as e:
            logging.error(f"Error in packet sniffing: {e}")
            self.running = False
            
    def stop(self):
        """Stop the firewall"""
        self.running = False
        logging.info("Firewall stopped")


if __name__ == "__main__":
    import sys
    
    # Check for root/admin privileges
    try:
        import os
        if os.geteuid() != 0:
            print("Error: This script requires root/administrator privileges")
            print("Please run with sudo: sudo python3 firewall.py")
            sys.exit(1)
    except AttributeError:
        # Windows doesn't have geteuid
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Error: This script requires administrator privileges")
            print("Please run as administrator")
            sys.exit(1)
    
    # Parse command line arguments
    interface = None
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    
    # Create and start firewall
    firewall = PersonalFirewall(interface=interface)
    firewall.start()
