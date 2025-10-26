#!/usr/bin/env python3
"""
Firewall CLI Management Tool
Manage firewall rules and view statistics
"""

import json
import sqlite3
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from tabulate import tabulate

class FirewallCLI:
    def __init__(self, rules_file='firewall_rules.json', db_path='firewall.db'):
        self.rules_file = rules_file
        self.db_path = db_path
        
    def load_rules(self):
        """Load current firewall rules"""
        if Path(self.rules_file).exists():
            with open(self.rules_file, 'r') as f:
                return json.load(f)
        return None
        
    def save_rules(self, rules):
        """Save firewall rules"""
        with open(self.rules_file, 'w') as f:
            json.dump(rules, f, indent=2)
        print("Rules saved successfully")
        
    def list_rules(self):
        """List all firewall rules"""
        rules = self.load_rules()
        if not rules:
            print("No rules file found")
            return
            
        print("\n=== Firewall Rules ===")
        print(f"Default Policy: {rules.get('default_policy', 'allow').upper()}")
        print("\nRules:")
        
        table_data = []
        for idx, rule in enumerate(rules.get('rules', []), 1):
            status = "✓" if rule.get('enabled', True) else "✗"
            table_data.append([
                idx,
                status,
                rule.get('name', 'Unnamed'),
                rule.get('action', 'N/A'),
                rule.get('protocol', 'any'),
                rule.get('dst_ports', 'any')
            ])
            
        print(tabulate(table_data, 
                      headers=['#', 'Status', 'Name', 'Action', 'Protocol', 'Ports'],
                      tablefmt='grid'))
        
        print(f"\nWhitelisted IPs: {', '.join(rules.get('whitelist_ips', []))}")
        print(f"Blacklisted IPs: {', '.join(rules.get('blacklist_ips', []))}")
        
    def add_rule(self, name, action, protocol=None, ports=None):
        """Add a new firewall rule"""
        rules = self.load_rules()
        if not rules:
            print("No rules file found")
            return
            
        new_rule = {
            'name': name,
            'action': action,
            'enabled': True
        }
        
        if protocol:
            new_rule['protocol'] = protocol
        if ports:
            new_rule['dst_ports'] = [int(p) for p in ports.split(',')]
            
        rules['rules'].append(new_rule)
        self.save_rules(rules)
        print(f"Rule '{name}' added successfully")
        
    def remove_rule(self, rule_idx):
        """Remove a firewall rule by index"""
        rules = self.load_rules()
        if not rules:
            print("No rules file found")
            return
            
        try:
            idx = int(rule_idx) - 1
            if 0 <= idx < len(rules['rules']):
                removed = rules['rules'].pop(idx)
                self.save_rules(rules)
                print(f"Rule '{removed['name']}' removed successfully")
            else:
                print("Invalid rule index")
        except ValueError:
            print("Invalid rule index")
            
    def toggle_rule(self, rule_idx):
        """Enable/disable a firewall rule"""
        rules = self.load_rules()
        if not rules:
            print("No rules file found")
            return
            
        try:
            idx = int(rule_idx) - 1
            if 0 <= idx < len(rules['rules']):
                rules['rules'][idx]['enabled'] = not rules['rules'][idx].get('enabled', True)
                status = "enabled" if rules['rules'][idx]['enabled'] else "disabled"
                self.save_rules(rules)
                print(f"Rule '{rules['rules'][idx]['name']}' {status}")
            else:
                print("Invalid rule index")
        except ValueError:
            print("Invalid rule index")
            
    def add_to_blacklist(self, ip):
        """Add IP to blacklist"""
        rules = self.load_rules()
        if not rules:
            print("No rules file found")
            return
            
        if 'blacklist_ips' not in rules:
            rules['blacklist_ips'] = []
            
        if ip not in rules['blacklist_ips']:
            rules['blacklist_ips'].append(ip)
            self.save_rules(rules)
            print(f"IP {ip} added to blacklist")
        else:
            print(f"IP {ip} already in blacklist")
            
    def remove_from_blacklist(self, ip):
        """Remove IP from blacklist"""
        rules = self.load_rules()
        if not rules:
            print("No rules file found")
            return
            
        if ip in rules.get('blacklist_ips', []):
            rules['blacklist_ips'].remove(ip)
            self.save_rules(rules)
            print(f"IP {ip} removed from blacklist")
        else:
            print(f"IP {ip} not in blacklist")
            
    def view_logs(self, log_type='blocked', limit=50):
        """View firewall logs"""
        if not Path(self.db_path).exists():
            print("No database found. Firewall may not have been run yet.")
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if log_type == 'blocked':
            cursor.execute('''
                SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, reason
                FROM blocked_packets
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            print(f"\n=== Last {limit} Blocked Packets ===")
            
        else:
            cursor.execute('''
                SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol
                FROM allowed_packets
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            print(f"\n=== Last {limit} Allowed Packets (sampled) ===")
            
        rows = cursor.fetchall()
        
        if rows:
            if log_type == 'blocked':
                headers = ['Timestamp', 'Source IP', 'Dest IP', 'Src Port', 'Dst Port', 'Protocol', 'Reason']
            else:
                headers = ['Timestamp', 'Source IP', 'Dest IP', 'Src Port', 'Dst Port', 'Protocol']
                
            print(tabulate(rows, headers=headers, tablefmt='grid'))
        else:
            print("No log entries found")
            
        conn.close()
        
    def view_statistics(self):
        """View firewall statistics"""
        if not Path(self.db_path).exists():
            print("No database found. Firewall may not have been run yet.")
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        print("\n=== Firewall Statistics ===")
        
        # Total blocked packets
        cursor.execute('SELECT COUNT(*) FROM blocked_packets')
        total_blocked = cursor.fetchone()[0]
        print(f"Total Blocked Packets: {total_blocked}")
        
        # Total allowed packets (sampled)
        cursor.execute('SELECT COUNT(*) FROM allowed_packets')
        total_allowed_sampled = cursor.fetchone()[0]
        print(f"Total Allowed Packets (sampled): {total_allowed_sampled}")
        
        # Top blocked IPs
        cursor.execute('''
            SELECT src_ip, COUNT(*) as count
            FROM blocked_packets
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        
        print("\nTop 10 Blocked Source IPs:")
        top_blocked = cursor.fetchall()
        if top_blocked:
            print(tabulate(top_blocked, headers=['IP Address', 'Block Count'], tablefmt='grid'))
        else:
            print("No blocked packets yet")
            
        # Blocks by reason
        cursor.execute('''
            SELECT reason, COUNT(*) as count
            FROM blocked_packets
            GROUP BY reason
            ORDER BY count DESC
        ''')
        
        print("\nBlocks by Reason:")
        blocks_by_reason = cursor.fetchall()
        if blocks_by_reason:
            print(tabulate(blocks_by_reason, headers=['Reason', 'Count'], tablefmt='grid'))
            
        # Recent 24h activity
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute('''
            SELECT COUNT(*) FROM blocked_packets
            WHERE timestamp > ?
        ''', (yesterday,))
        recent_blocks = cursor.fetchone()[0]
        print(f"\nBlocks in last 24 hours: {recent_blocks}")
        
        # Threat intelligence stats
        cursor.execute('SELECT COUNT(*) FROM threat_intel')
        threat_count = cursor.fetchone()[0]
        print(f"Known Malicious IPs in Database: {threat_count}")
        
        conn.close()
        
    def view_threats(self):
        """View threat intelligence data"""
        if not Path(self.db_path).exists():
            print("No database found. Firewall may not have been run yet.")
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip, threat_level, last_seen, source
            FROM threat_intel
            ORDER BY last_seen DESC
            LIMIT 50
        ''')
        
        rows = cursor.fetchall()
        
        if rows:
            print("\n=== Threat Intelligence Database (Last 50) ===")
            print(tabulate(rows, 
                          headers=['IP Address', 'Threat Level', 'Last Seen', 'Source'],
                          tablefmt='grid'))
        else:
            print("No threat intelligence data found")
            
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='Personal Firewall CLI Management Tool')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List rules
    subparsers.add_parser('list', help='List all firewall rules')
    
    # Add rule
    add_parser = subparsers.add_parser('add', help='Add a new rule')
    add_parser.add_argument('name', help='Rule name')
    add_parser.add_argument('action', choices=['allow', 'block'], help='Action to take')
    add_parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp'], help='Protocol')
    add_parser.add_argument('--ports', help='Comma-separated port numbers')
    
    # Remove rule
    remove_parser = subparsers.add_parser('remove', help='Remove a rule')
    remove_parser.add_argument('index', help='Rule index to remove')
    
    # Toggle rule
    toggle_parser = subparsers.add_parser('toggle', help='Enable/disable a rule')
    toggle_parser.add_argument('index', help='Rule index to toggle')
    
    # Blacklist commands
    blacklist_parser = subparsers.add_parser('blacklist', help='Manage IP blacklist')
    blacklist_parser.add_argument('action', choices=['add', 'remove'], help='Action')
    blacklist_parser.add_argument('ip', help='IP address')
    
    # View logs
    logs_parser = subparsers.add_parser('logs', help='View firewall logs')
    logs_parser.add_argument('--type', choices=['blocked', 'allowed'], default='blocked', help='Log type')
    logs_parser.add_argument('--limit', type=int, default=50, help='Number of entries to show')
    
    # View statistics
    subparsers.add_parser('stats', help='View firewall statistics')
    
    # View threats
    subparsers.add_parser('threats', help='View threat intelligence data')
    
    args = parser.parse_args()
    cli = FirewallCLI()
    
    if args.command == 'list':
        cli.list_rules()
    elif args.command == 'add':
        cli.add_rule(args.name, args.action, args.protocol, args.ports)
    elif args.command == 'remove':
        cli.remove_rule(args.index)
    elif args.command == 'toggle':
        cli.toggle_rule(args.index)
    elif args.command == 'blacklist':
        if args.action == 'add':
            cli.add_to_blacklist(args.ip)
        else:
            cli.remove_from_blacklist(args.ip)
    elif args.command == 'logs':
        cli.view_logs(args.type, args.limit)
    elif args.command == 'stats':
        cli.view_statistics()
    elif args.command == 'threats':
        cli.view_threats()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()