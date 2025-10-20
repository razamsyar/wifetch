#!/usr/bin/env python3
"""
WiFetch - Cross-platform WiFi Credential Recovery
Retrieves saved WiFi passwords on Windows, Linux, and macOS
Author: sqlj3d1
"""

import subprocess
import platform
import re
import os
import sys
import json
import argparse
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Union


def colored_print(text: str, color: str = None) -> None:
    """Print text (colors disabled)"""
    print(text)


def print_banner():
    """Display welcome banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                      WiFetch v1.0                            ║
║          Cross-Platform WiFi Credential Recovery             ║
║                                                              ║
║          Author: sqlj3d1                                     ║
║          GitHub: https://github.com/razamsyar                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    colored_print("[*] Fetching saved WiFi credentials...")
    colored_print(f"[+] Platform: {platform.system()} {platform.release()}")
    print()


class WiFiPasswordViewer:
    def __init__(self):
        self.system = platform.system()
        self.profiles: List[Dict[str, str]] = []
        self.errors: List[str] = []

    def check_privileges(self) -> bool:
        """Check if script has necessary privileges"""
        try:
            if self.system == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Linux/macOS
                return os.geteuid() == 0
        except (ImportError, AttributeError, OSError) as e:
            self.errors.append(f"Error checking privileges: {e}")
            return False

    def get_wifi_passwords_windows(self) -> bool:
        """Retrieve WiFi passwords on Windows"""
        try:
            # Get all profiles
            profiles_output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profiles'],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30
            )
            
            # Extract profile names
            profile_lines = re.findall(r'All User Profile\s*:\s*(.+)', profiles_output)
            
            if not profile_lines:
                colored_print("[!] No WiFi profiles found")
                return True
            
            colored_print(f"[*] Found {len(profile_lines)} WiFi profiles")
            
            for profile in profile_lines:
                profile = profile.strip()
                try:
                    # Get profile details with password
                    profile_info = subprocess.check_output(
                        ['netsh', 'wlan', 'show', 'profile', f'name={profile}', 'key=clear'],
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=15
                    )
                    
                    # Extract password
                    password_match = re.search(r'Key Content\s*:\s*(.+)', profile_info)
                    password = password_match.group(1).strip() if password_match else "<no stored key>"
                    
                    # Extract security type
                    security_match = re.search(r'Security key\s*:\s*(.+)', profile_info)
                    security_type = security_match.group(1).strip() if security_match else "Unknown"
                    
                    self.profiles.append({
                        'network': profile,
                        'password': password,
                        'security_type': security_type,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                except subprocess.TimeoutExpired:
                    self.errors.append(f"Timeout retrieving profile: {profile}")
                    self.profiles.append({
                        'network': profile,
                        'password': "<timeout>",
                        'security_type': "Unknown",
                        'timestamp': datetime.now().isoformat()
                    })
        except subprocess.CalledProcessError as e:
                    self.errors.append(f"Error retrieving profile '{profile}': {e}")
                    self.profiles.append({
                        'network': profile,
                        'password': "<error retrieving>",
                        'security_type': "Unknown",
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except subprocess.TimeoutExpired:
            colored_print("[!] Timeout while retrieving WiFi profiles")
            return False
        except subprocess.CalledProcessError as e:
            colored_print(f"[!] Error accessing WiFi profiles: {e}")
            return False
        except FileNotFoundError:
            colored_print("[!] netsh command not found. Are you on Windows?")
            return False
        except Exception as e:
            colored_print(f"[!] Unexpected error: {e}")
            return False
            
        return True

    def get_wifi_passwords_linux(self) -> bool:
        """Retrieve WiFi passwords on Linux (NetworkManager and wpa_supplicant)"""
        profiles_found = False
        
        # Try NetworkManager first
        nm_path = Path('/etc/NetworkManager/system-connections/')
        if nm_path.exists():
            try:
                colored_print("[*] Checking NetworkManager connections...")
                for conn_file in nm_path.iterdir():
                    if conn_file.is_file() and conn_file.suffix == '':
                        try:
                            with open(conn_file, 'r', encoding='utf-8') as f:
                                content = f.read()
                                
                            # Extract SSID from [wifi] section
                            ssid_match = re.search(r'\[wifi\].*?ssid=(.+)', content, re.DOTALL)
                            if ssid_match:
                                ssid = ssid_match.group(1).strip()
                            else:
                                # Fallback to filename if SSID not found in content
                                ssid = conn_file.stem
                            
                            # Extract password and security info from [wifi-security] section
                            password = "<no stored key>"
                            security_type = "Open"
                            
                            # Look for psk (pre-shared key) in wifi-security section
                            psk_match = re.search(r'\[wifi-security\].*?psk=(.+)', content, re.DOTALL)
                            if psk_match:
                                password = psk_match.group(1).strip()
                                security_type = "WPA/WPA2"
                            
                            # Check key-mgmt for additional security type info
                            key_mgmt_match = re.search(r'\[wifi-security\].*?key-mgmt=(.+)', content, re.DOTALL)
                            if key_mgmt_match:
                                key_mgmt = key_mgmt_match.group(1).strip()
                                if key_mgmt == "wpa-psk":
                                    security_type = "WPA/WPA2"
                                elif key_mgmt == "wep":
                                    security_type = "WEP"
                            
                            self.profiles.append({
                                'network': ssid,
                                'password': password,
                                'security_type': security_type,
                                'timestamp': datetime.now().isoformat()
                            })
                            profiles_found = True
                            
                        except PermissionError:
                            self.errors.append(f"Permission denied reading {conn_file}")
                            continue
                        except (UnicodeDecodeError, Exception) as e:
                            self.errors.append(f"Error reading {conn_file}: {e}")
                            continue
            except PermissionError:
                colored_print("[!] Permission denied accessing NetworkManager files")
                return False
        
        # Try wpa_supplicant
        wpa_supplicant_paths = [
            '/etc/wpa_supplicant/wpa_supplicant.conf',
            '/etc/wpa_supplicant.conf',
            f'/home/{os.getenv("USER", "root")}/.config/wpa_supplicant/wpa_supplicant.conf'
        ]
        
        for wpa_path in wpa_supplicant_paths:
            wpa_file = Path(wpa_path)
            if wpa_file.exists():
                try:
                    colored_print(f"[*] Checking wpa_supplicant config: {wpa_path}")
                    with open(wpa_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Extract network blocks
                    network_blocks = re.findall(r'network\s*=\s*\{([^}]+)\}', content, re.DOTALL)
                    
                    for block in network_blocks:
                        ssid_match = re.search(r'ssid\s*=\s*"([^"]+)"', block)
                        psk_match = re.search(r'psk\s*=\s*"([^"]+)"', block)
                        
                        if ssid_match:
                            ssid = ssid_match.group(1)
                            password = psk_match.group(1) if psk_match else "<no stored key>"
                            security_type = "WPA/WPA2" if psk_match else "Open"
                            
                            self.profiles.append({
                                'network': ssid,
                                'password': password,
                                'security_type': security_type,
                                'timestamp': datetime.now().isoformat()
                            })
                            profiles_found = True
                            
                except (PermissionError, UnicodeDecodeError) as e:
                    self.errors.append(f"Error reading {wpa_path}: {e}")
                    continue
        
        # Try iw command for currently connected networks
        try:
            colored_print("[*] Checking currently connected networks...")
            iw_output = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT, text=True, timeout=10)
            # This is a basic implementation - could be enhanced further
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass  # iw command not available or failed
        
        if not profiles_found:
            colored_print("[!] No WiFi profiles found in NetworkManager or wpa_supplicant")
            colored_print("[!] Your system might use a different network manager")
            return False
        
        return True

    def get_wifi_passwords_macos(self) -> bool:
        """Retrieve WiFi passwords on macOS"""
        try:
            colored_print("[*] Accessing macOS keychain for WiFi passwords...")
            
            # Get WiFi networks from keychain
            networks_cmd = subprocess.check_output(
                ['security', 'dump-keychain'],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30
            )
            
            # Extract WiFi networks from keychain
            wifi_entries = re.findall(r'"acct"<blob>="(.+?)"', networks_cmd)
            
            if not wifi_entries:
                colored_print("[!] No WiFi networks found in keychain")
                return True
            
            colored_print(f"[*] Found {len(set(wifi_entries))} WiFi networks in keychain")
            
            for network in set(wifi_entries):
                try:
                    # Get password for each network
                    password_output = subprocess.check_output(
                        ['security', 'find-generic-password', '-D', 'AirPort network password', 
                         '-a', network, '-w'],
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=10
                    )
                    password = password_output.strip()
                    
                    self.profiles.append({
                        'network': network,
                        'password': password,
                        'security_type': "WPA/WPA2",  # Most macOS networks are WPA/WPA2
                        'timestamp': datetime.now().isoformat()
                    })
                    
                except subprocess.TimeoutExpired:
                    self.errors.append(f"Timeout retrieving password for {network}")
                    self.profiles.append({
                        'network': network,
                        'password': "<timeout>",
                        'security_type': "Unknown",
                        'timestamp': datetime.now().isoformat()
                    })
        except subprocess.CalledProcessError as e:
                    self.errors.append(f"Error retrieving password for {network}: {e}")
                    self.profiles.append({
                        'network': network,
                        'password': "<error retrieving>",
                        'security_type': "Unknown",
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except subprocess.TimeoutExpired:
            colored_print("[!] Timeout accessing keychain")
            return False
        except subprocess.CalledProcessError as e:
            colored_print(f"[!] Error accessing keychain: {e}")
            return False
        except FileNotFoundError:
            colored_print("[!] security command not found. Are you on macOS?")
            return False
        except Exception as e:
            colored_print(f"[!] Unexpected error: {e}")
            return False
        
        return True

    def get_passwords(self) -> bool:
        """Main method to retrieve passwords based on OS"""
        if self.system == "Windows":
            return self.get_wifi_passwords_windows()
        elif self.system == "Linux":
            return self.get_wifi_passwords_linux()
        elif self.system == "Darwin":  # macOS
            return self.get_wifi_passwords_macos()
        else:
            colored_print(f"[!] Unsupported operating system: {self.system}")
            return False

    def search_network(self, query: str) -> List[Dict[str, str]]:
        """Enhanced search for specific network with highlighting"""
        if not query:
            return self.profiles
        
        query_processed = query.lower()
        results = []
        
        for profile in self.profiles:
            network_name = profile['network'].lower()
            if query_processed in network_name:
                # Add highlighting for search results
                highlighted_profile = profile.copy()
                highlighted_profile['highlighted'] = True
                results.append(highlighted_profile)
        
        return results

    def display_table(self, profiles: Optional[List[Dict[str, str]]] = None):
        """Display passwords in enhanced table format with colors"""
        if profiles is None:
            profiles = self.profiles
        
        if not profiles:
            colored_print("No WiFi profiles found.")
            return
        
        # Calculate column widths
        max_network_len = max(len(p['network']) for p in profiles)
        max_network_len = max(max_network_len, len("Network Name"))
        max_password_len = max(len(p['password']) for p in profiles)
        max_password_len = max(max_password_len, len("Password"))
        max_security_len = max(len(p.get('security_type', 'Unknown')) for p in profiles)
        max_security_len = max(max_security_len, len("Security"))
        
        # Print header
        header = f"{'Network Name':<{max_network_len}} | {'Password':<{max_password_len}} | {'Security':<{max_security_len}}"
        header_length = len(header)
        print("\n" + "="*header_length)
        colored_print(header)
        print("="*header_length)
        
        # Print profiles with colors
        for profile in profiles:
            network = profile['network']
            password = profile['password']
            security = profile.get('security_type', 'Unknown')
            
            # Color coding for passwords
            if password in ['<no stored key>', '<error retrieving>', '<timeout>']:
                password_color = ""
            elif len(password) < 8:
                password_color = ""
            else:
                password_color = ""
            
            # Color coding for security types
            if 'WPA3' in security:
                security_color = ""
            elif 'WPA2' in security or 'WPA' in security:
                security_color = ""
            elif 'Open' in security:
                security_color = ""
            else:
                security_color = ""
            
            # Highlight search results
            if profile.get('highlighted', False):
                network_color = ""
            else:
                network_color = ""
            
            # Format each field with colors
            network_str = f"{network:<{max_network_len}}"
            password_str = f"{password:<{max_password_len}}"
            security_str = f"{security:<{max_security_len}}"
            
            # Apply colors
            colored_network = f"{network_color}{network_str}{""}"
            colored_password = f"{password_color}{password_str}{""}"
            colored_security = f"{security_color}{security_str}{""}"
            
            print(f"{colored_network} | {colored_password} | {colored_security}")
        
        print("="*header_length)
        colored_print(f"\nTotal networks found: {len(profiles)}")
        
        # Show errors if any
        if self.errors:
            colored_print(f"\nErrors encountered: {len(self.errors)}")
            for error in self.errors[:5]:  # Show first 5 errors
                colored_print(f"  - {error}")
            if len(self.errors) > 5:
                colored_print(f"  ... and {len(self.errors) - 5} more errors")
        print()

    def export_to_file(self, filename: str, format_type: str = None) -> bool:
        """Export passwords to file with multiple formats"""
        try:
            # Default to txt if no format specified
            if format_type is None:
                format_type = 'txt'
            
            if format_type == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.profiles, f, indent=2, ensure_ascii=False)
                colored_print(f"Exported to {filename} (JSON format)")
                
            elif format_type == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    if self.profiles:
                        writer = csv.DictWriter(f, fieldnames=self.profiles[0].keys())
                        writer.writeheader()
                        writer.writerows(self.profiles)
                colored_print(f"Exported to {filename} (CSV format)")
                
            elif format_type == 'xml':
                root = ET.Element('wifi_profiles')
                for profile in self.profiles:
                    profile_elem = ET.SubElement(root, 'profile')
                    for key, value in profile.items():
                        elem = ET.SubElement(profile_elem, key)
                        elem.text = str(value)
                
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)
                colored_print(f"Exported to {filename} (XML format)")
                
            else:  # txt
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("WiFi Password Export\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Networks: {len(self.profiles)}\n\n")
                    
                    for profile in self.profiles:
                        f.write(f"Network: {profile['network']}\n")
                        f.write(f"Password: {profile['password']}\n")
                        f.write(f"Security: {profile.get('security_type', 'Unknown')}\n")
                        f.write(f"Timestamp: {profile.get('timestamp', 'Unknown')}\n")
                        f.write("\n")
                colored_print(f"Exported to {filename} (Text format)")
            
            
            return True
            
        except PermissionError:
            colored_print(f"[!] Permission denied writing to {filename}")
            return False
        except Exception as e:
            colored_print(f"[!] Error exporting to file: {e}")
            return False


def validate_input(args) -> bool:
    """Validate command line arguments"""
    if args.search and len(args.search.strip()) == 0:
        colored_print("[!] Search query cannot be empty")
        return False
    
    if args.export and not args.export.strip():
        colored_print("[!] Export filename cannot be empty")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description='WiFetch - Cross-platform WiFi Credential Recovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 %(prog)s                          # List all WiFi passwords
  python3 %(prog)s -q                       # Quiet mode (minimal output)
  python3 %(prog)s -s Home           # Search for specific network
  python3 %(prog)s -e wifipass.txt          # Export to text file (default)
  python3 %(prog)s -e wifipass.json -f json # Export to JSON format
  python3 %(prog)s -e wifipass.csv -f csv   # Export to CSV format
  python3 %(prog)s -e wifipass.xml -f xml   # Export to XML format
  python3 %(prog)s -s Home -e wifipass.json -f json  # Search and export as JSON

Platform Requirements:
  Windows: Run as Administrator
  Linux:   Run with sudo
  macOS:   Run with sudo

Author: sqlj3d1
GitHub: https://github.com/razamsyar
        """
    )
    
    parser.add_argument('-s', '--search', metavar='NETWORK', 
                        help='Search for specific network name')
    parser.add_argument('-e', '--export', metavar='FILE',
                        help='Export passwords to file')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'xml'],
                        help='Export format (default: txt)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode - minimal output')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not validate_input(args):
        sys.exit(1)
    
    # Display banner
    if not args.quiet:
        print_banner()
    
    viewer = WiFiPasswordViewer()
    
    # Check privileges
    if not viewer.check_privileges():
        colored_print("[!] ERROR: Elevated privileges required")
        if viewer.system == "Windows":
            colored_print("[!] Run as Administrator (Right-click -> Run as administrator)")
        else:
            colored_print("[!] Run with sudo: sudo python3 wifetch.py")
        sys.exit(1)
    
    if not args.quiet:
        colored_print(f"[*] Scanning WiFi passwords on {viewer.system}...")
        print()
    
    # Get passwords
    if not viewer.get_passwords():
        colored_print("[!] Failed to retrieve WiFi passwords")
        sys.exit(1)
    
    # Get profiles
    profiles = viewer.profiles
    
    # Handle search
    if args.search:
        results = viewer.search_network(args.search)
        if results:
            if not args.quiet:
                colored_print(f"Search results for '{args.search}':")
            viewer.display_table(results)
            # Update profiles to only include search results for export
            viewer.profiles = results
        else:
            colored_print(f"No networks found matching '{args.search}'")
    else:
        # Display all
        viewer.display_table(profiles)
    
    # Handle export
    if args.export:
        success = viewer.export_to_file(args.export, args.format)
        if not success:
            sys.exit(1)

if __name__ == "__main__":
    main()