import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP
import logging
from typing import Dict, List, Set
import sys
import re
import whois
from urllib.parse import urlparse

# Configuration
CONFIG_FILE = "0s_cyber_security_config.json"

class AccurateOS:
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.command_history = []
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_bot = None
        self.logs = []
        self.threat_alerts = []
        self.setup_logging()
        self.load_config()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('0s_cyber_security.log'),
                logging.StreamHandler()
            ]
        )
        
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            
    def save_config(self):
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")
    
    # PING IP COMMAND
    def ping_ip(self, ip):
        """Ping an IP address and return results"""
        try:
            param = '-n' if os.name == 'nt' else '-c'
            result = subprocess.run(['ping', param, '4', ip], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Ping successful to {ip}\n{result.stdout}"
            else:
                return f"❌ Ping failed to {ip}\n{result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Ping timeout to {ip}"
        except Exception as e:
            return f"❌ Ping error: {e}"
    
    # ANALYZE IP COMMAND - NEW FEATURE
    def analyze_ip(self, ip):
        """Comprehensive IP analysis for cybersecurity"""
        try:
            socket.inet_aton(ip)
            analysis_report = []
            
            # Basic IP information
            analysis_report.append("🟣" + "="*60)
            analysis_report.append("🟣 COMPREHENSIVE IP ANALYSIS REPORT")
            analysis_report.append("🟣" + "="*60)
            analysis_report.append(f"🟣 Target IP: {ip}")
            analysis_report.append(f"🟣 Analysis Time: {datetime.now()}")
            analysis_report.append("")
            
            # 1. Ping test
            analysis_report.append("🟣 1. NETWORK REACHABILITY TEST")
            analysis_report.append("🟣" + "-"*40)
            ping_result = self.ping_ip(ip)
            if "successful" in ping_result:
                analysis_report.append("🟣 Status: 🟢 HOST IS REACHABLE")
            else:
                analysis_report.append("🟣 Status: 🔴 HOST IS UNREACHABLE")
            analysis_report.append("")
            
            # 2. Port scanning (quick)
            analysis_report.append("🟣 2. PORT VULNERABILITY ASSESSMENT")
            analysis_report.append("🟣" + "-"*40)
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                            # Security assessment
                            if port in [21, 23, 135, 139, 445]:
                                analysis_report.append(f"🟣 ⚠️  RISKY PORT OPEN: {port} (Potential security risk)")
                            elif port in [22, 80, 443]:
                                analysis_report.append(f"🟣 🟡 STANDARD PORT OPEN: {port} (Common service)")
                            else:
                                analysis_report.append(f"🟣 🟢 NORMAL PORT OPEN: {port}")
                except:
                    continue
            
            if not open_ports:
                analysis_report.append("🟣 🟢 No common ports open (Good security posture)")
            analysis_report.append("")
            
            # 3. Geographical and ISP information
            analysis_report.append("🟣 3. GEOGRAPHICAL & NETWORK INFORMATION")
            analysis_report.append("🟣" + "-"*40)
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                data = response.json()
                if data['status'] == 'success':
                    analysis_report.append(f"🟣 Country: {data.get('country', 'N/A')}")
                    analysis_report.append(f"🟣 Region: {data.get('regionName', 'N/A')}")
                    analysis_report.append(f"🟣 City: {data.get('city', 'N/A')}")
                    analysis_report.append(f"🟣 ISP: {data.get('isp', 'N/A')}")
                    analysis_report.append(f"🟣 Organization: {data.get('org', 'N/A')}")
                    
                    # Threat intelligence based on location/ISP
                    risky_countries = ['Russia', 'China', 'North Korea', 'Iran']
                    if data.get('country') in risky_countries:
                        analysis_report.append("🟣 ⚠️  WARNING: IP located in high-risk country")
                    if 'cloud' in data.get('isp', '').lower():
                        analysis_report.append("🟣 ℹ️  Note: IP belongs to cloud service provider")
                else:
                    analysis_report.append("🟣 Location data unavailable")
            except:
                analysis_report.append("🟣 Location lookup failed")
            analysis_report.append("")
            
            # 4. DNS and Reverse DNS lookup
            analysis_report.append("🟣 4. DNS ANALYSIS")
            analysis_report.append("🟣" + "-"*40)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                analysis_report.append(f"🟣 Reverse DNS: {hostname}")
                
                # Check for suspicious hostname patterns
                suspicious_patterns = ['tor', 'proxy', 'vpn', 'anonymous']
                if any(pattern in hostname.lower() for pattern in suspicious_patterns):
                    analysis_report.append("🟣 ⚠️  SUSPICIOUS: Hostname contains anonymity-related terms")
            except:
                analysis_report.append("🟣 Reverse DNS lookup failed")
            analysis_report.append("")
            
            # 5. Threat Intelligence Summary
            analysis_report.append("🟣 5. THREAT INTELLIGENCE SUMMARY")
            analysis_report.append("🟣" + "-"*40)
            
            risk_score = 0
            if len(open_ports) > 5:
                risk_score += 2
                analysis_report.append("🟣 ⚠️  Multiple ports open (Increased attack surface)")
            
            risky_ports_open = any(port in [21, 23, 135, 139, 445] for port in open_ports)
            if risky_ports_open:
                risk_score += 3
                analysis_report.append("🟣 ⚠️  High-risk ports detected (Potential vulnerability)")
            
            # Final risk assessment
            analysis_report.append("")
            analysis_report.append("🟣" + "="*60)
            if risk_score >= 3:
                analysis_report.append("🟣 🔴 HIGH RISK: Immediate attention recommended")
            elif risk_score >= 1:
                analysis_report.append("🟣 🟡 MEDIUM RISK: Monitor and investigate")
            else:
                analysis_report.append("🟣 🟢 LOW RISK: Normal security posture")
            analysis_report.append("🟣" + "="*60)
            
            return "\n".join(analysis_report)
            
        except socket.error:
            return f"❌ Invalid IP address: {ip}"
        except Exception as e:
            return f"❌ Analysis error: {e}"
    
    # START MONITORING IP COMMAND
    def start_monitoring_ip(self, ip):
        """Start monitoring a specific IP address"""
        try:
            socket.inet_aton(ip)
            self.monitored_ips.add(ip)
            self.monitoring_active = True
            self.save_config()
            
            log_msg = f"🟣 Started monitoring IP: {ip} at {datetime.now()}"
            self.logs.append(log_msg)
            logging.info(log_msg)
            
            return f"✅ Started monitoring IP: {ip}\n📊 Total monitored IPs: {len(self.monitored_ips)}"
        except socket.error:
            return f"❌ Invalid IP address: {ip}"
        except Exception as e:
            return f"❌ Error starting monitoring: {e}"
    
    # SCAN IP COMMAND (Quick Scan)
    def scan_ip(self, ip, port_range=(1, 1000)):
        """Quick port scan on an IP address"""
        try:
            socket.inet_aton(ip)
            open_ports = []
            start_port, end_port = port_range
            
            logging.info(f"🔍 Starting quick scan on {ip} (ports {start_port}-{end_port})")
            
            for port in range(start_port, end_port + 1):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                except:
                    continue
            
            if open_ports:
                return f"✅ Scan completed for {ip}\n🟢 Open ports: {sorted(open_ports)}"
            else:
                return f"✅ Scan completed for {ip}\n🔴 No open ports found in range {start_port}-{end_port}"
                
        except socket.error:
            return f"❌ Invalid IP address: {ip}"
        except Exception as e:
            return f"❌ Scan error: {e}"
    
    # DEEP SCAN IP COMMAND (Full Scan)
    def deep_scan_ip(self, ip):
        """Deep port scan on an IP address (more ports)"""
        try:
            socket.inet_aton(ip)
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 
                          445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
            
            logging.info(f"🔍 Starting deep scan on {ip}")
            
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                except:
                    continue
            
            additional_ranges = [(1000, 2000), (3000, 4000), (5000, 6000), (7000, 8000)]
            
            for start, end in additional_ranges:
                for port in range(start, end + 1):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(1)
                            result = sock.connect_ex((ip, port))
                            if result == 0:
                                open_ports.append(port)
                    except:
                        continue
            
            if open_ports:
                return f"✅ Deep scan completed for {ip}\n🟢 Open ports: {sorted(open_ports)}"
            else:
                return f"✅ Deep scan completed for {ip}\n🔴 No open ports found"
                
        except socket.error:
            return f"❌ Invalid IP address: {ip}"
        except Exception as e:
            return f"❌ Deep scan error: {e}"
    
    # LOCATION IP COMMAND
    def location_ip(self, ip):
        """Get geographical location information for an IP address"""
        try:
            socket.inet_aton(ip)
            
            logging.info(f"📍 Getting location for IP: {ip}")
            
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = response.json()
            
            if data['status'] == 'success':
                location_info = f"""
🟣 Location Information for {ip}:

🟣 Country: {data.get('country', 'N/A')}
🟣 Region: {data.get('regionName', 'N/A')}
🟣 City: {data.get('city', 'N/A')}
🟣 ZIP: {data.get('zip', 'N/A')}
🟣 ISP: {data.get('isp', 'N/A')}
🟣 Organization: {data.get('org', 'N/A')}
🟣 Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}
                """
                return location_info.strip()
            else:
                return f"❌ Could not retrieve location for {ip}"
                
        except socket.error:
            return f"❌ Invalid IP address: {ip}"
        except requests.RequestException as e:
            return f"❌ Network error getting location: {e}"
        except Exception as e:
            return f"❌ Location lookup error: {e}"
    
    # NMAP SCAN COMMAND
    def nmap_scan(self, ip, options=""):
        """Perform nmap scan with various options"""
        try:
            socket.inet_aton(ip)
            
            if not self.check_nmap_installed():
                return "❌ nmap is not installed. Please install nmap to use this feature."
            
            cmd = f"nmap {options} {ip}"
            logging.info(f"Running nmap command: {cmd}")
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return f"✅ Nmap scan completed for {ip}\n{result.stdout}"
            else:
                return f"❌ Nmap scan failed: {result.stderr}"
                
        except socket.error:
            return f"❌ Invalid IP address: {ip}"
        except subprocess.TimeoutExpired:
            return f"⏰ Nmap scan timed out for {ip}"
        except Exception as e:
            return f"❌ Nmap scan error: {e}"
    
    def check_nmap_installed(self):
        """Check if nmap is installed on the system"""
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            return True
        except:
            return False
    
    # CURL COMMANDS
    def curl_fetch(self, url):
        """Fetch URL content using curl"""
        try:
            result = subprocess.run(f"curl -s {url}", shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ URL content fetched successfully:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch URL: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_save(self, url, output_file):
        """Save URL content to file using curl"""
        try:
            result = subprocess.run(f"curl -s -o {output_file} {url}", shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content saved to {output_file}"
            else:
                return f"❌ Failed to save content: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_user_agent(self, url, user_agent):
        """Fetch URL with custom user agent"""
        try:
            result = subprocess.run(f'curl -s -A "{user_agent}" {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content fetched with custom User-Agent:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch with custom User-Agent: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_referer(self, url, referer):
        """Fetch URL with custom referer"""
        try:
            result = subprocess.run(f'curl -s -e "{referer}" {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content fetched with custom Referer:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch with custom Referer: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_proxy(self, url, proxy):
        """Fetch URL through proxy"""
        try:
            result = subprocess.run(f'curl -s -x "{proxy}" {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content fetched through proxy:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch through proxy: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_headers(self, url, headers):
        """Fetch URL with custom headers"""
        try:
            header_cmd = " ".join([f'-H "{h}"' for h in headers.split(",")])
            result = subprocess.run(f'curl -s {header_cmd} {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content fetched with custom headers:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch with custom headers: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_auth(self, url, credentials):
        """Fetch URL with authentication"""
        try:
            result = subprocess.run(f'curl -s -u "{credentials}" {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content fetched with authentication:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch with authentication: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_follow_redirects(self, url):
        """Fetch URL following redirects"""
        try:
            result = subprocess.run(f'curl -s -L {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content fetched following redirects:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch following redirects: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_cookie_file(self, url, cookie_file):
        """Fetch URL with cookie file"""
        try:
            result = subprocess.run(f'curl -s -b "{cookie_file}" {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Content fetched with cookies:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch with cookies: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_save_cookies(self, url, cookie_file):
        """Save cookies from URL to file"""
        try:
            result = subprocess.run(f'curl -s -c "{cookie_file}" {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Cookies saved to {cookie_file}"
            else:
                return f"❌ Failed to save cookies: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    def curl_compressed(self, url):
        """Fetch URL with compression"""
        try:
            result = subprocess.run(f'curl -s --compressed {url}', shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"✅ Compressed content fetched:\n\n{result.stdout}"
            else:
                return f"❌ Failed to fetch compressed content: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"⏰ Request timed out for {url}"
        except Exception as e:
            return f"❌ Curl error: {e}"
    
    # NETCAT COMMAND
    def netcat_help(self):
        """Show netcat help"""
        try:
            result = subprocess.run(["nc", "-h"], capture_output=True, text=True)
            return f"🟣 Netcat Help:\n\n{result.stdout if result.stdout else result.stderr}"
        except Exception as e:
            return f"❌ Netcat error: {e}"
    
    # CLEAR SCREEN COMMAND
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return "🟣 Screen cleared"
    
    # VIEW ALL HISTORY COMMAND
    def view_all_history(self):
        """View all command history"""
        if self.command_history:
            return "🟣 Complete Command History:\n" + "\n".join([f"{i+1}. {cmd}" for i, cmd in enumerate(self.command_history)])
        else:
            return "🟣 No command history available"
    
    # Additional utility methods
    def stop_monitoring(self):
        """Stop all monitoring activities"""
        self.monitoring_active = False
        log_msg = "🟣 Monitoring stopped"
        self.logs.append(log_msg)
        logging.info(log_msg)
        return "✅ Monitoring stopped"
    
    def get_status(self):
        """Get current monitoring status"""
        status = f"""
🟣 Accurate OS Status:

🟣 Monitoring Active: {self.monitoring_active}
🟣 Monitored IPs: {len(self.monitored_ips)}
🟣 Threat Alerts: {len(self.threat_alerts)}
🟣 Log Entries: {len(self.logs)}
🟣 Command History: {len(self.command_history)}
        """
        return status.strip()
    
    def view_monitored_ips(self):
        """View all monitored IP addresses"""
        if self.monitored_ips:
            return f"🟣 Monitored IPs ({len(self.monitored_ips)}):\n" + "\n".join([f"  • {ip}" for ip in self.monitored_ips])
        else:
            return "🟣 No IPs currently being monitored"
    
    def add_ip(self, ip):
        """Add an IP to monitoring list"""
        try:
            socket.inet_aton(ip)
            if ip in self.monitored_ips:
                return f"ℹ️ IP {ip} is already being monitored"
            self.monitored_ips.add(ip)
            self.save_config()
            return f"✅ Added IP: {ip} to monitoring list"
        except socket.error:
            return f"❌ Invalid IP address: {ip}"
    
    def remove_ip(self, ip):
        """Remove an IP from monitoring list"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.save_config()
            return f"✅ Removed IP: {ip} from monitoring list"
        return f"❌ IP {ip} not found in monitoring list"

class TelegramBotHandler:
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_update_id = 0
        
    def send_telegram_message(self, message):
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.monitor.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, json=payload)
            return response.status_code == 200
        except Exception as e:
            logging.error(f"Telegram send error: {e}")
            return False
            
    def get_updates(self):
        if not self.monitor.telegram_token:
            return []
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/getUpdates"
            params = {'offset': self.last_update_id + 1, 'timeout': 30}
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                if data['ok']:
                    return data['result']
            return []
        except Exception as e:
            logging.error(f"Telegram update error: {e}")
            return []
            
    def process_telegram_commands(self):
        updates = self.get_updates()
        for update in updates:
            self.last_update_id = update['update_id']
            if 'message' in update and 'text' in update['message']:
                message = update['message']['text']
                chat_id = update['message']['chat']['id']
                self.monitor.telegram_chat_id = chat_id
                self.handle_telegram_command(message, chat_id)
                
    def handle_telegram_command(self, command, chat_id):
        command = command.strip()
        self.monitor.command_history.append(f"TELEGRAM: {command}")
        
        if command == '/help':
            help_text = """
🟣 <b>Accurate Online OS</b> 🟣

<b>Core Commands:</b>
/ping_ip [IP] - Ping an IP address
/analyze_ip [IP] - Comprehensive security analysis
/start_monitoring_ip [IP] - Start monitoring IP
/scan_ip [IP] - Quick port scan (1-1000)
/deep_scan_ip [IP] - Deep port scan
/location_ip [IP] - Get IP location information

<b>NMAP Commands:</b>
/nmap [IP] - Basic nmap scan
/nmap_os [IP] - OS detection scan
/nmap_services [IP] - Service version detection
/nmap_vuln [IP] - Vulnerability scan

<b>CURL Commands:</b>
/curl [URL] - Fetch URL content
/curl_save [URL] [file] - Save response to file
/curl_ua [URL] [UA] - Custom user agent
/curl_referer [URL] [referer] - Custom referer
/curl_proxy [URL] [proxy] - Use proxy
/curl_headers [URL] [headers] - Custom headers
/curl_auth [URL] [user:pass] - Authentication
/curl_redirects [URL] - Follow redirects
/curl_cookies [URL] [file] - Use cookies
/curl_save_cookies [URL] [file] - Save cookies
/curl_compressed [URL] - Compressed transfer

<b>Monitoring Management:</b>
/stop_monitoring - Stop all monitoring
/status - Show monitoring status
/view_ips - View monitored IPs
/add_ip [IP] - Add IP to monitoring
/remove_ip [IP] - Remove IP from monitoring

<b>Additional Commands:</b>
/clear - Clear screen
/history_all - View all command history
/nc_help - Netcat help
/help - Show this help message
/history - View command history
/export_data - Export monitoring data
            """
            self.send_telegram_message(help_text)
            
        elif command.startswith('/ping_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.ping_ip(ip)
                self.send_telegram_message(f"🏓 {result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address. Usage: /ping_ip 192.168.1.1")
                
        elif command.startswith('/analyze_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.analyze_ip(ip)
                # Split long messages for Telegram
                if len(result) > 4000:
                    parts = [result[i:i+4000] for i in range(0, len(result), 4000)]
                    for part in parts:
                        self.send_telegram_message(f"🔍 {part}")
                        time.sleep(1)
                else:
                    self.send_telegram_message(f"🔍 {result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address. Usage: /analyze_ip 192.168.1.1")
                
        elif command.startswith('/start_monitoring_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.start_monitoring_ip(ip)
                self.send_telegram_message(result)
            else:
                self.send_telegram_message("❌ Please provide an IP address. Usage: /start_monitoring_ip 192.168.1.1")
                
        elif command.startswith('/scan_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.scan_ip(ip)
                self.send_telegram_message(f"🔍 {result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address. Usage: /scan_ip 192.168.1.1")
                
        elif command.startswith('/deep_scan_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.deep_scan_ip(ip)
                self.send_telegram_message(f"🔍 {result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address. Usage: /deep_scan_ip 192.168.1.1")
                
        elif command.startswith('/location_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.location_ip(ip)
                self.send_telegram_message(result)
            else:
                self.send_telegram_message("❌ Please provide an IP address. Usage: /location_ip 192.168.1.1")
                
        elif command == '/stop_monitoring':
            result = self.monitor.stop_monitoring()
            self.send_telegram_message(result)
            
        elif command == '/status':
            status = self.monitor.get_status()
            self.send_telegram_message(status)
            
        elif command == '/view_ips':
            ips = self.monitor.view_monitored_ips()
            self.send_telegram_message(ips)
            
        elif command.startswith('/add_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.add_ip(ip)
                self.send_telegram_message(result)
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command.startswith('/remove_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.remove_ip(ip)
                self.send_telegram_message(result)
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command == '/history':
            history = "\n".join(self.monitor.command_history[-10:]) if self.monitor.command_history else "No command history"
            self.send_telegram_message(f"📜 Recent Commands:\n{history}")
                
        elif command == '/export_data':
            data = f"Accurate OS Export - {datetime.now()}\nMonitored IPs: {len(self.monitor.monitored_ips)}\nLogs: {len(self.monitor.logs)}"
            self.send_telegram_message(f"📊 {data}")
                
        else:
            self.send_telegram_message("❌ Unknown command. Type /help for available commands.")

def main():
    monitor = AccurateOS()
    telegram_handler = TelegramBotHandler(monitor)
    
    # Start Telegram handler in separate thread
    def telegram_worker():
        while True:
            try:
                telegram_handler.process_telegram_commands()
                time.sleep(2)
            except Exception as e:
                logging.error(f"Telegram worker error: {e}")
                time.sleep(10)
    
    telegram_thread = threading.Thread(target=telegram_worker, daemon=True)
    telegram_thread.start()
    
    # Main interface with purple theme
    def print_purple(text):
        print(f"\033[95m{text}\033[0m")
        
    def print_banner():
        banner = """
        🟣 ================================================================
        🟣      Villain ONLINE OS  
        🟣 ================================================================
        🟣    
        🟣   Community: https://github.com/Accurate-Cyber-Defense
        🟣
        🟣   
        🟣   Advanced Network Scanning & Security Analysis
        🟣   
        🟣 ================================================================
        """
        print_purple(banner)
    
    def show_help():
        help_text = """
        🟣 CORE SECURITY COMMANDS:
        
        🔍 IP Analysis Commands:
          ping [ip]              - Ping an IP address
          analyze [ip]           - Comprehensive security analysis
          monitor [ip]           - Start monitoring an IP
          scan [ip]              - Quick port scan (1-1000)
          deepscan [ip]          - Deep port scan (common + extended ports)
          location [ip]          - Get geographical location information
        
        🛠️  NMAP Scanning Commands:
          nmap [ip]              - Basic nmap scan
          nmap -sS [ip]          - TCP SYN scan
          nmap -sU [ip]          - UDP scan  
          nmap -O [ip]           - OS detection
          nmap -sV [ip]          - Service version detection
          nmap -A [ip]           - Aggressive scan
          nmap -p [ports] [ip]   - Specific port scan
          nmap --script [ip]     - NSE script scan
        
        🌐 CURL Commands:
          curl [url]             - Fetch URL content
          curl -o [file] [url]   - Save response to file
          curl -A "[ua]" [url]   - Custom user agent
          curl -e "[ref]" [url]  - Custom referer
          curl -x "[proxy]" [url]- Use proxy
          curl -H "[headers]" [url] - Custom headers
          curl -u "[auth]" [url] - Authentication
          curl -L [url]          - Follow redirects
          curl -b [file] [url]   - Use cookies from file
          curl -c [file] [url]   - Save cookies to file
          curl --compressed [url] - Compressed transfer
        
        📊 Monitoring Management:
          status                 - Show current monitoring status
          view                   - View all monitored IPs
          add [ip]               - Add IP to monitoring list
          remove [ip]            - Remove IP from monitoring list
          stop                   - Stop all monitoring activities
        
        ⚙️  Utility Commands:
          clear                  - Clear the terminal screen
          history_all            - View complete command history
          nc_help                - Show netcat help
          history                - View recent command history
          config token [value]   - Configure Telegram token
          config chat_id [value] - Configure Telegram chat ID
          export                 - Export data to Telegram
          help                   - Show this help message
          exit                   - Exit the program
        """
        print_purple(help_text)
    
    print_banner()
    show_help()
    
    # Command processing
    while True:
        try:
            command = input("\n\033[95maccurateOS> \033[0m").strip()
            monitor.command_history.append(command)
            
            if command == 'exit':
                print_purple("👋 Exiting Accurate Cyber Security OS...")
                break
                
            elif command == 'help':
                show_help()
                
            elif command == 'clear':
                result = monitor.clear_screen()
                print_purple(result)
                print_banner()
                
            elif command == 'history_all':
                result = monitor.view_all_history()
                print_purple(result)
                
            elif command == 'nc_help':
                result = monitor.netcat_help()
                print_purple(result)
                
            elif command.startswith('ping '):
                ip = command.split(' ')[1]
                result = monitor.ping_ip(ip)
                print_purple(result)
                
            elif command.startswith('analyze '):
                ip = command.split(' ')[1]
                print_purple("🟣 Starting comprehensive security analysis...")
                result = monitor.analyze_ip(ip)
                print_purple(result)
                
            elif command.startswith('monitor '):
                ip = command.split(' ')[1]
                result = monitor.start_monitoring_ip(ip)
                print_purple(result)
                
            elif command.startswith('scan '):
                ip = command.split(' ')[1]
                result = monitor.scan_ip(ip)
                print_purple(result)
                
            elif command.startswith('deepscan '):
                ip = command.split(' ')[1]
                result = monitor.deep_scan_ip(ip)
                print_purple(result)
                
            elif command.startswith('location '):
                ip = command.split(' ')[1]
                result = monitor.location_ip(ip)
                print_purple(result)
                
            elif command.startswith('nmap '):
                parts = command.split(' ')
                if len(parts) >= 2:
                    ip = parts[-1]
                    options = " ".join(parts[1:-1])
                    result = monitor.nmap_scan(ip, options)
                    print_purple(result)
                else:
                    print_purple("❌ Usage: nmap [options] [ip]")
                    
            elif command.startswith('curl '):
                parts = command.split(' ')
                if len(parts) >= 2:
                    url = parts[-1]
                    options = " ".join(parts[1:-1])
                    
                    if '-o' in options:
                        # Save to file
                        try:
                            file_index = parts.index('-o') + 1
                            output_file = parts[file_index]
                            url = parts[file_index + 1]
                            result = monitor.curl_save(url, output_file)
                        except:
                            result = "❌ Usage: curl -o [output_file] [url]"
                    elif '-A' in options:
                        # Custom user agent
                        try:
                            ua_index = parts.index('-A') + 1
                            user_agent = parts[ua_index]
                            url = parts[ua_index + 1]
                            result = monitor.curl_user_agent(url, user_agent)
                        except:
                            result = "❌ Usage: curl -A \"User Agent\" [url]"
                    elif '-e' in options:
                        # Custom referer
                        try:
                            ref_index = parts.index('-e') + 1
                            referer = parts[ref_index]
                            url = parts[ref_index + 1]
                            result = monitor.curl_referer(url, referer)
                        except:
                            result = "❌ Usage: curl -e \"http://referer.com\" [url]"
                    elif '-x' in options:
                        # Proxy
                        try:
                            proxy_index = parts.index('-x') + 1
                            proxy = parts[proxy_index]
                            url = parts[proxy_index + 1]
                            result = monitor.curl_proxy(url, proxy)
                        except:
                            result = "❌ Usage: curl -x \"proxy:port\" [url]"
                    elif '-H' in options:
                        # Custom headers
                        try:
                            header_index = parts.index('-H') + 1
                            headers = parts[header_index]
                            url = parts[header_index + 1]
                            result = monitor.curl_headers(url, headers)
                        except:
                            result = "❌ Usage: curl -H \"Header: Value\" [url]"
                    elif '-u' in options:
                        # Authentication
                        try:
                            auth_index = parts.index('-u') + 1
                            credentials = parts[auth_index]
                            url = parts[auth_index + 1]
                            result = monitor.curl_auth(url, credentials)
                        except:
                            result = "❌ Usage: curl -u \"user:pass\" [url]"
                    elif '-L' in options:
                        # Follow redirects
                        result = monitor.curl_follow_redirects(url)
                    elif '-b' in options:
                        # Cookie file
                        try:
                            cookie_index = parts.index('-b') + 1
                            cookie_file = parts[cookie_index]
                            url = parts[cookie_index + 1]
                            result = monitor.curl_cookie_file(url, cookie_file)
                        except:
                            result = "❌ Usage: curl -b cookie_file [url]"
                    elif '-c' in options:
                        # Save cookies
                        try:
                            cookie_index = parts.index('-c') + 1
                            cookie_file = parts[cookie_index]
                            url = parts[cookie_index + 1]
                            result = monitor.curl_save_cookies(url, cookie_file)
                        except:
                            result = "❌ Usage: curl -c cookie_file [url]"
                    elif '--compressed' in options:
                        # Compressed
                        result = monitor.curl_compressed(url)
                    else:
                        # Basic curl
                        result = monitor.curl_fetch(url)
                    print_purple(result)
                else:
                    print_purple("❌ Usage: curl [options] [url]")
                
            elif command == 'stop':
                result = monitor.stop_monitoring()
                print_purple(result)
                
            elif command == 'status':
                status = monitor.get_status()
                print_purple(status)
                
            elif command == 'view':
                ips = monitor.view_monitored_ips()
                print_purple(ips)
                
            elif command.startswith('add '):
                ip = command.split(' ')[1]
                result = monitor.add_ip(ip)
                print_purple(result)
                
            elif command.startswith('remove '):
                ip = command.split(' ')[1]
                result = monitor.remove_ip(ip)
                print_purple(result)
                
            elif command == 'history':
                history = "\n".join(monitor.command_history[-10:]) if monitor.command_history else "No command history"
                print_purple(f"📜 Recent Commands:\n{history}")
                
            elif command.startswith('config token '):
                token = command.split(' ')[2]
                monitor.telegram_token = token
                monitor.save_config()
                print_purple("✅ Telegram token configured successfully")
                
            elif command.startswith('config chat_id '):
                chat_id = command.split(' ')[2]
                monitor.telegram_chat_id = chat_id
                monitor.save_config()
                print_purple("✅ Telegram chat ID configured successfully")
                
            elif command == 'export':
                data = f"Accurate OS Export - {datetime.now()}\nMonitored IPs: {len(monitor.monitored_ips)}"
                if telegram_handler.send_telegram_message(data):
                    print_purple("✅ Data exported to Telegram successfully")
                else:
                    print_purple("❌ Failed to export data to Telegram")
                    
            else:
                print_purple("❌ Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print_purple("\n👋 Exiting Villain Online OS...")
            break
        except Exception as e:
            print_purple(f"❌ Error: {e}")

if __name__ == "__main__":
    # Install required packages
    required_packages = ['scapy', 'requests']
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
    
    main()