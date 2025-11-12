import sys
import threading
import datetime
import eel
import re
import urllib.parse
import json
import hashlib
import psutil
import tkinter as tk
from tkinter import filedialog
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, Raw, conf, ARP, ICMP, wrpcap
import queue
import time
import sqlite3
import uuid
import os
import socket
import bcrypt
from typing import Dict, List, Optional, Any
from functools import wraps

try:
    from scapy.layers.http import HTTPRequest
except ImportError:
    HTTPRequest = None

try:
    from scapy.layers.tls.all import TLS
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    TLS = TLSClientHello = DNS = DNSQR = DNSRR = None


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- MODIFIED: Correctly locate files from the project's root directory ---
# Determine the absolute path to the project's root directory (one level up from 'app')
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE = resource_path("app_data.db")
# --- END MODIFICATION ---

# Thread locks for thread safety
db_lock = threading.Lock()
cache_lock = threading.Lock()
raw_packets_lock = threading.Lock()

# Login attempt tracking
login_attempts = defaultdict(list)
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_LOCKOUT_DURATION = 300  # 5 minutes

# Global variables with thread safety
raw_packets_store: Dict[str, Any] = {}
dns_cache: Dict[str, str] = {}
reverse_dns_cache: Dict[str, str] = {}


class SecurityManager:
    """Enhanced security management class"""

    @staticmethod
    def validate_input(data: str, field_type: str = "general") -> bool:
        """Validate user input based on field type"""
        if not data or len(data.strip()) == 0:
            return False

        # Length limits
        if len(data) > 255:
            return False

        if field_type == "username":
            # Username: alphanumeric, underscore, dash only
            return bool(re.match(r'^[a-zA-Z0-9_-]{3,50}$', data))
        elif field_type == "password":
            # Password: minimum 8 characters
            return len(data) >= 8
        elif field_type == "activation_code":
            # Activation code: alphanumeric only
            return bool(re.match(r'^[a-zA-Z0-9]{6,50}$', data))
        else:
            # General: no special characters that could be used for injection
            dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
            return not any(char in data for char in dangerous_chars)

    @staticmethod
    def is_login_allowed(username: str, client_ip: str = "unknown") -> tuple[bool, str]:
        """Check if login attempts are within limits"""
        key = f"{username}_{client_ip}"
        now = time.time()

        # Clean old attempts
        login_attempts[key] = [
            attempt_time for attempt_time in login_attempts[key]
            if now - attempt_time < LOGIN_LOCKOUT_DURATION
        ]

        if len(login_attempts[key]) >= LOGIN_ATTEMPT_LIMIT:
            return False, "Too many failed attempts. Please try again in 5 minutes."

        return True, ""

    @staticmethod
    def record_failed_login(username: str, client_ip: str = "unknown"):
        """Record a failed login attempt"""
        key = f"{username}_{client_ip}"
        login_attempts[key].append(time.time())

    @staticmethod
    def clear_login_attempts(username: str, client_ip: str = "unknown"):
        """Clear login attempts after successful login"""
        key = f"{username}_{client_ip}"
        login_attempts[key] = []


class DatabaseManager:
    """Enhanced database management with better error handling"""

    @staticmethod
    def init_database():
        """Initialize database with proper error handling"""
        try:
            with db_lock:
                conn = sqlite3.connect(DB_FILE, timeout=10.0)
                cursor = conn.cursor()

                # Enable foreign keys
                cursor.execute("PRAGMA foreign_keys = ON")

                # Create users table with additional security fields
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        activation_code TEXT NOT NULL,
                        machine_id TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1,
                        failed_login_count INTEGER DEFAULT 0
                    )
                ''')

                # Create login attempts table for tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN DEFAULT 0
                    )
                ''')

                # NEW: Create packets table for storage
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS packets (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        src TEXT,
                        dst TEXT,
                        src_full TEXT,
                        dst_full TEXT,
                        protocol TEXT,
                        domain TEXT,
                        info TEXT,
                        size INTEGER,
                        src_port INTEGER,
                        dst_port INTEGER,
                        sensitive_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                conn.commit()

        except sqlite3.Error as e:
            raise Exception(f"Database error: {e}")
        except Exception as e:
            raise
        finally:
            try:
                conn.close()
            except:
                pass

    @staticmethod
    def execute_query(query: str, params: tuple = (), fetch_one: bool = False, fetch_all: bool = False) -> Any:
        """Execute database query with proper error handling and connection management"""
        try:
            with db_lock:
                conn = sqlite3.connect(DB_FILE, timeout=10.0)
                cursor = conn.cursor()
                cursor.execute(query, params)

                result = None
                if fetch_one:
                    result = cursor.fetchone()
                elif fetch_all:
                    result = cursor.fetchall()

                conn.commit()
                return result

        except sqlite3.IntegrityError as e:
            raise Exception("Data integrity violation")
        except sqlite3.Error as e:
            raise Exception(f"Database error: {e}")
        except Exception as e:
            raise
        finally:
            try:
                conn.close()
            except:
                pass


class AuthenticationManager:
    """Enhanced authentication with bcrypt"""

    @staticmethod
    def get_machine_id() -> str:
        """Generate machine-specific identifier"""
        try:
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            return hashlib.sha256(mac.encode()).hexdigest()
        except Exception as e:
            return "unknown_machine"

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        try:
            # Generate salt and hash password
            salt = bcrypt.gensalt(rounds=12)
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            return password_hash.decode('utf-8')
        except Exception as e:
            raise Exception("Password hashing failed")

    @staticmethod
    def verify_password(password: str, hash_from_db: str) -> bool:
        """Verify password against bcrypt hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_from_db.encode('utf-8'))
        except Exception as e:
            return False


def handle_errors(func):
    """Decorator for consistent error handling"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return {'status': 'error', 'message': f'An unexpected error occurred: {str(e)}'}

    return wrapper


class DomainResolver:
    """Enhanced domain resolution class with better error handling"""

    @staticmethod
    def resolve_ip_to_domain(ip_address: str) -> Optional[str]:
        """Try to resolve IP to domain using multiple methods with thread safety"""
        try:
            with cache_lock:
                # First check our DNS cache
                if ip_address in dns_cache:
                    return dns_cache[ip_address]

                # Check reverse DNS cache
                if ip_address in reverse_dns_cache:
                    return reverse_dns_cache[ip_address]

            # Try reverse DNS lookup (non-blocking with timeout)
            try:
                socket.setdefaulttimeout(2.0)  # 2 second timeout
                domain = socket.gethostbyaddr(ip_address)[0]
                if domain and domain != ip_address:
                    with cache_lock:
                        reverse_dns_cache[ip_address] = domain
                    return domain
            except (socket.herror, socket.gaierror, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)

            # Check if it's a known service IP
            known_domain = DomainResolver.get_known_service_domain(ip_address)
            if known_domain:
                with cache_lock:
                    reverse_dns_cache[ip_address] = known_domain
                return known_domain

        except Exception as e:
            pass

        return None

    @staticmethod
    def get_known_service_domain(ip_address: str) -> Optional[str]:
        """Map known service IPs to their domains"""
        try:
            # Common service IP ranges and their domains
            known_services = {
                # Google services
                '8.8.8.8': 'dns.google',
                '8.8.4.4': 'dns.google',
                '1.1.1.1': 'cloudflare-dns.com',
                '1.0.0.1': 'cloudflare-dns.com',
            }

            # Check for IP ranges
            if ip_address.startswith('172.217.') or ip_address.startswith('74.125.'):
                return 'google.com'
            elif ip_address.startswith('31.13.') or ip_address.startswith('69.171.'):
                return 'facebook.com'
            elif ip_address.startswith('157.240.'):
                return 'facebook.com'

            return known_services.get(ip_address)

        except Exception as e:
            return None

    @staticmethod
    def extract_domain_from_payload(payload_text: str) -> Optional[str]:
        """Extract domain from HTTP payload with better error handling"""
        try:
            # Look for Host header
            host_match = re.search(r'Host:\s*([^\r\n]+)', payload_text, re.IGNORECASE)
            if host_match:
                return host_match.group(1).strip()

            # Look for Referer header
            referer_match = re.search(r'Referer:\s*https?://([^/\r\n]+)', payload_text, re.IGNORECASE)
            if referer_match:
                return referer_match.group(1).strip()

            # Look for common URL patterns in payload
            url_patterns = [
                r'https?://([^/\s\r\n"\'<>]+)',
                r'"url"\s*:\s*"https?://([^/\s\r\n"\'<>]+)',
                r'"domain"\s*:\s*"([^"\s\r\n]+)',
                r'"host"\s*:\s*"([^"\s\r\n]+)',
            ]

            for pattern in url_patterns:
                match = re.search(pattern, payload_text, re.IGNORECASE)
                if match:
                    domain = match.group(1).strip()
                    if '.' in domain and not domain.replace('.', '').replace('-', '').isdigit():
                        return domain

        except Exception as e:
            pass

        return None


class PacketAnalyzer:
    """Enhanced packet analyzer with better error handling"""

    def __init__(self):
        self.sensitive_patterns = [
            re.compile(r'(?:^|&)(?:username|user|login|email|mail|utilizador|usuario)=([^&\s]+)', re.IGNORECASE),
            re.compile(r'(?:^|&)(?:password|pass|pwd|passwd|senha|contrasena)=([^&\s]+)', re.IGNORECASE),
            re.compile(r'(?:^|&)(?:token|key|secret|auth|session|csrf)=([^&\s]+)', re.IGNORECASE),
            re.compile(r'"(?:username|user|login|email|mail)"\s*:\s*"([^"]+)"', re.IGNORECASE),
            re.compile(r'"(?:password|pass|pwd|passwd)"\s*:\s*"([^"]+)"', re.IGNORECASE),
            re.compile(r'"(?:token|key|secret|auth|session)"\s*:\s*"([^"]+)"', re.IGNORECASE),
        ]
        self.domain_resolver = DomainResolver()

    def extract_sensitive_data(self, packet) -> List[Dict[str, str]]:
        """Extract sensitive data with enhanced error handling"""
        found_data = []
        try:
            if HTTPRequest and packet.haslayer(HTTPRequest):
                http_req = packet[HTTPRequest]
                if hasattr(http_req, 'load') and http_req.load:
                    try:
                        post_data = http_req.load.decode('utf-8', errors='ignore')
                        found_data.extend(self.search_credentials_in_text(post_data, "HTTP POST"))
                    except Exception as e:
                        pass

            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    found_data.extend(self.search_credentials_in_text(payload, "Raw Payload"))
                except Exception as e:
                    pass

        except Exception as e:
            pass

        # Remove duplicates
        unique_findings = list({json.dumps(d, sort_keys=True): d for d in found_data}.values())
        return unique_findings

    def search_credentials_in_text(self, text: str, source: str = "") -> List[Dict[str, str]]:
        """Search for credentials with better validation"""
        findings = []
        try:
            for pattern in self.sensitive_patterns:
                matches = pattern.findall(text)
                for match in matches:
                    try:
                        decoded_match = urllib.parse.unquote_plus(str(match))
                    except Exception:
                        decoded_match = str(match)

                    # Validate the match
                    if decoded_match and len(decoded_match.strip()) > 1:
                        # Skip obviously false positives
                        if not self.is_likely_credential(decoded_match):
                            continue

                        field_type = self.detect_field_type(pattern.pattern)
                        findings.append({
                            "type": field_type,
                            "value": decoded_match.strip(),
                            "source": source
                        })
        except Exception as e:
            pass

        return findings

    def is_likely_credential(self, value: str) -> bool:
        """Check if a value is likely to be a real credential"""
        value = value.strip().lower()

        # Skip common false positives
        false_positives = {
            'null', 'none', 'undefined', 'empty', 'test', 'example',
            'placeholder', 'default', 'admin', 'root', 'user', 'guest',
            '123456', 'password', 'pass', 'pwd', 'secret'
        }

        if value in false_positives:
            return False

        # Must have minimum length
        if len(value) < 3:
            return False

        # Skip values that are all the same character
        if len(set(value)) == 1:
            return False

        return True

    def detect_field_type(self, pattern: str) -> str:
        """Detect credential field type from pattern"""
        p_lower = pattern.lower()
        if 'password' in p_lower or 'pass' in p_lower or 'pwd' in p_lower:
            return "Password"
        if 'username' in p_lower or 'user' in p_lower:
            return "Username"
        if 'email' in p_lower or 'mail' in p_lower:
            return "Email"
        if 'token' in p_lower or 'key' in p_lower or 'secret' in p_lower:
            return "Token/Key"
        return "Credential"

    def process_http_packet(self, packet, packet_info: Dict[str, Any]) -> bool:
        """Process HTTP packet for domain extraction"""
        domain_found = False
        try:
            if HTTPRequest and packet.haslayer(HTTPRequest):
                http_req = packet[HTTPRequest]
                if hasattr(http_req, 'Host') and http_req.Host:
                    packet_info['domain'] = http_req.Host.decode(errors='ignore')
                    domain_found = True

                # Build request info
                method = http_req.Method.decode(errors='ignore') if hasattr(http_req, 'Method') and http_req.Method else 'GET'
                path = http_req.Path.decode(errors='ignore') if hasattr(http_req, 'Path') and http_req.Path else '/'
                packet_info['info'] = f"{method} {path}"

            # If no domain from HTTP headers, try payload analysis
            if not domain_found and packet.haslayer(Raw):
                try:
                    payload_text = packet[Raw].load.decode('utf-8', errors='ignore')
                    extracted_domain = self.domain_resolver.extract_domain_from_payload(payload_text)
                    if extracted_domain:
                        packet_info['domain'] = extracted_domain
                        domain_found = True
                except Exception as e:
                    pass

        except Exception as e:
            pass

        return domain_found

    def process_https_packet(self, packet, packet_info: Dict[str, Any]) -> bool:
        """Process HTTPS packet for domain extraction"""
        domain_found = False
        try:
            # Try to extract SNI from TLS handshake
            if TLS and TLSClientHello and packet.haslayer(TLSClientHello):
                try:
                    tls_layer = packet[TLSClientHello]
                    if hasattr(tls_layer, 'ext') and tls_layer.ext:
                        for ext in tls_layer.ext:
                            if hasattr(ext, 'servernames') and ext.servernames:
                                for servername in ext.servernames:
                                    if hasattr(servername, 'servername'):
                                        packet_info['domain'] = servername.servername.decode(errors='ignore')
                                        domain_found = True
                                        break
                            if domain_found:
                                break
                except Exception as e:
                    pass

            packet_info['info'] = "TLS Handshake" if not packet_info.get('info') else packet_info['info']
        except Exception as e:
            pass

        return domain_found

    def process_ftp_packet(self, packet, packet_info: Dict[str, Any]) -> bool:
        """Process FTP packet for domain extraction"""
        domain_found = False
        try:
            if packet.haslayer(Raw):
                try:
                    payload_text = packet[Raw].load.decode('utf-8', errors='ignore')
                    extracted_domain = self.domain_resolver.extract_domain_from_payload(payload_text)
                    if extracted_domain:
                        packet_info['domain'] = extracted_domain
                        domain_found = True
                except Exception as e:
                    pass
        except Exception as e:
            pass

        return domain_found

    def process_dns_packet(self, packet, packet_info: Dict[str, Any]) -> bool:
        """Process DNS packet for domain extraction"""
        domain_found = False
        try:
            dns_layer = packet[DNS]
            if hasattr(dns_layer, 'qd') and dns_layer.qd:
                query_name = dns_layer.qd.qname.decode(errors='ignore').rstrip('.')
                packet_info['domain'] = query_name
                domain_found = True

                # Determine query type
                if dns_layer.qr == 0:  # Query
                    packet_info['info'] = f"Query for {query_name}"
                else:  # Response
                    packet_info['info'] = f"Response for {query_name}"
        except Exception as e:
            pass

        return domain_found

    def analyze_packet(self, packet, get_full_details: bool = False) -> Dict[str, Any]:
        """Enhanced packet analysis with better error handling"""
        try:
            time_str = datetime.datetime.now().strftime("%H:%M:%S")
            packet_info = {
                'id': hashlib.md5(bytes(packet)).hexdigest()[:10],
                'time': time_str,
                'src': 'N/A',
                'dst': 'N/A',
                'proto': 'Unknown',
                'domain': 'N/A',
                'info': '',
                'size': len(packet),
                'sensitive_data': [],
                'src_port': None,
                'dst_port': None
            }

            # Extract sensitive data
            try:
                packet_info['sensitive_data'] = self.extract_sensitive_data(packet)
            except Exception as e:
                pass

            domain_found = False

            # Enhanced DNS response processing
            if DNS and packet.haslayer(DNS):
                try:
                    dns_layer = packet[DNS]
                    if dns_layer.qr == 1 and hasattr(dns_layer, 'an') and dns_layer.an:  # Response
                        for i in range(min(dns_layer.ancount, 10)):  # Limit to prevent issues
                            try:
                                answer = dns_layer.an[i] if i == 0 else dns_layer.an[i]
                                if hasattr(answer, 'type') and answer.type == 1:  # A record
                                    name = answer.rrname.decode(errors='ignore').rstrip('.')
                                    ip = str(answer.rdata) if hasattr(answer, 'rdata') else None
                                    if name and ip and ip != 'None':
                                        with cache_lock:
                                            dns_cache[ip] = name
                            except (AttributeError, IndexError, UnicodeDecodeError) as e:
                                continue
                except Exception as e:
                    pass

            if IP in packet:
                try:
                    ip_layer = packet[IP]
                    packet_info.update({
                        'src': ip_layer.src,
                        'dst': ip_layer.dst,
                        'proto': ip_layer.get_field('proto').i2s.get(ip_layer.proto, f'IP-{ip_layer.proto}')
                    })

                    if TCP in packet:
                        tcp_layer = packet[TCP]
                        packet_info.update({
                            'src_full': f"{ip_layer.src}:{tcp_layer.sport}",
                            'dst_full': f"{ip_layer.dst}:{tcp_layer.dport}",
                            'src_port': tcp_layer.sport,
                            'dst_port': tcp_layer.dport
                        })

                        # Protocol-specific processing with error handling
                        try:
                            if tcp_layer.dport in {80, 8080} or tcp_layer.sport in {80, 8080}:
                                packet_info['proto'] = 'HTTP'
                                domain_found = self.process_http_packet(packet, packet_info)

                            elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                                packet_info['proto'] = 'HTTPS'
                                domain_found = self.process_https_packet(packet, packet_info)

                            elif tcp_layer.dport in {20, 21} or tcp_layer.sport in {20, 21}:
                                packet_info['proto'] = 'FTP'
                                domain_found = self.process_ftp_packet(packet, packet_info)

                            else:
                                packet_info['proto'] = f'TCP:{tcp_layer.dport}'
                        except Exception as e:
                            pass

                    elif UDP in packet:
                        udp_layer = packet[UDP]
                        packet_info.update({
                            'src_full': f"{ip_layer.src}:{udp_layer.sport}",
                            'dst_full': f"{ip_layer.dst}:{udp_layer.dport}",
                            'src_port': udp_layer.sport,
                            'dst_port': udp_layer.dport
                        })

                        try:
                            if DNS and (udp_layer.dport == 53 or udp_layer.sport == 53):
                                packet_info['proto'] = 'DNS'
                                domain_found = self.process_dns_packet(packet, packet_info)
                            else:
                                packet_info['proto'] = f'UDP:{udp_layer.dport}'
                        except Exception as e:
                            pass

                    # Enhanced domain resolution fallback
                    if not domain_found:
                        try:
                            resolved_domain = self.domain_resolver.resolve_ip_to_domain(ip_layer.dst)
                            if resolved_domain:
                                packet_info['domain'] = resolved_domain
                                domain_found = True

                            if not domain_found:
                                resolved_domain = self.domain_resolver.resolve_ip_to_domain(ip_layer.src)
                                if resolved_domain:
                                    packet_info['domain'] = resolved_domain
                                    domain_found = True
                        except Exception as e:
                            pass

                except Exception as e:
                    pass

            elif ARP in packet:
                try:
                    arp_layer = packet[ARP]
                    packet_info.update({
                        'proto': 'ARP',
                        'src': arp_layer.psrc,
                        'dst': arp_layer.pdst,
                        'src_full': arp_layer.hwsrc,
                        'dst_full': arp_layer.hwdst,
                        'info': f"Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
                    })
                except Exception as e:
                    pass

            # Clean up domain name
            if packet_info['domain'] != 'N/A':
                try:
                    packet_info['domain'] = packet_info['domain'].lower().strip()
                    if packet_info['domain'].startswith('www.'):
                        packet_info['domain'] = packet_info['domain'][4:]
                except Exception as e:
                    pass

            # Add detailed information if requested
            if get_full_details:
                try:
                    packet_info['raw_hex'] = bytes(packet).hex()
                    if IP in packet:
                        packet_info['ip_ttl'] = packet[IP].ttl
                        packet_info['ip_flags'] = str(packet[IP].flags)
                    if TCP in packet:
                        packet_info['tcp_flags'] = str(packet[TCP].flags)
                        packet_info['tcp_seq'] = packet[TCP].seq
                        packet_info['tcp_ack'] = packet[TCP].ack
                        packet_info['tcp_window'] = packet[TCP].window
                except Exception as e:
                    pass

            # NEW: Store packet in database for pagination
            try:
                self.store_packet_in_db(packet_info)
            except Exception as e:
                pass

            return packet_info

        except Exception as e:
            # Return basic packet info even if analysis fails
            return {
                'id': 'error',
                'time': datetime.datetime.now().strftime("%H:%M:%S"),
                'src': 'N/A',
                'dst': 'N/A',
                'proto': 'Error',
                'domain': 'N/A',
                'info': 'Analysis failed',
                'size': 0,
                'sensitive_data': [],
                'src_port': None,
                'dst_port': None
            }

    def store_packet_in_db(self, packet_info: Dict[str, Any]):
        """Store packet information in database"""
        try:
            DatabaseManager.execute_query(
                """INSERT OR REPLACE INTO packets 
                   (id, timestamp, src, dst, src_full, dst_full, protocol, domain, info, size, src_port, dst_port, sensitive_data) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    packet_info['id'],
                    packet_info['time'],
                    packet_info['src'],
                    packet_info['dst'],
                    packet_info.get('src_full'),
                    packet_info.get('dst_full'),
                    packet_info['proto'],
                    packet_info['domain'],
                    packet_info['info'],
                    packet_info['size'],
                    packet_info.get('src_port'),
                    packet_info.get('dst_port'),
                    json.dumps(packet_info['sensitive_data'])
                )
            )
        except Exception as e:
            pass


class SniffingThread(threading.Thread):
    """Enhanced sniffing thread with better error handling and thread safety"""

    def __init__(self, interface_obj, bpf_filter: str):
        super().__init__()
        self.daemon = True
        self.interface_obj = interface_obj
        self.bpf_filter = bpf_filter
        self.analyzer = PacketAnalyzer()
        self._stop_event = threading.Event()
        self.packet_queue = queue.Queue(maxsize=1000)  # Prevent memory issues

    def run(self):
        """Main sniffing loop with enhanced error handling"""
        ui_update_thread = threading.Thread(target=self.batch_update_ui, daemon=True)
        ui_update_thread.start()

        try:
            while not self._stop_event.is_set():
                try:
                    sniff(
                        iface=self.interface_obj.name,
                        prn=self.process_packet,
                        filter=self.bpf_filter,
                        store=False,
                        count=0,
                        timeout=1
                    )
                except OSError as e:
                    if "The system cannot find the device specified" in str(e):
                        error_message = "Network interface not available. Please select a different interface."
                    else:
                        error_message = f"Network access error: {str(e)}. Try running as administrator."
                    eel.show_error(error_message)
                    break
                except Exception as e:
                    error_message = f"Sniffing error: {str(e)}. Try running as administrator."
                    eel.show_error(error_message)
                    break

        except Exception as e:
            pass
        finally:
            eel.update_sniff_status(False)

    def stop(self):
        """Stop the sniffing thread safely"""
        self._stop_event.set()

    def process_packet(self, packet):
        """Process individual packets with error handling"""
        try:
            packet_summary = self.analyzer.analyze_packet(packet, get_full_details=False)
            if packet_summary and packet_summary['id'] != 'error':
                # Store raw packet with thread safety
                with raw_packets_lock:
                    raw_packets_store[packet_summary['id']] = packet

                # Add to queue (non-blocking)
                try:
                    self.packet_queue.put(packet_summary, block=False)
                except queue.Full:
                    pass

        except Exception as e:
            pass

    def batch_update_ui(self):
        """Batch UI updates for better performance"""
        BATCH_SIZE = 50
        MAX_WAIT_SECONDS = 0.5

        while not self._stop_event.is_set():
            packets_batch = []
            start_time = time.time()

            while (len(packets_batch) < BATCH_SIZE and
                   (time.time() - start_time) < MAX_WAIT_SECONDS):
                try:
                    packet = self.packet_queue.get(timeout=0.1)
                    packets_batch.append(packet)
                except queue.Empty:
                    break

            if packets_batch:
                try:
                    eel.add_packets_to_ui(packets_batch)
                except Exception as e:
                    pass

            if not packets_batch:
                time.sleep(0.1)


# Global sniffing thread with thread safety
sniffer_thread = None
sniffer_lock = threading.Lock()


# NEW: Add function to clear packets from database
@eel.expose
@handle_errors
def clear_packets_db() -> Dict[str, str]:
    """Clear all packets from database"""
    try:
        DatabaseManager.execute_query("DELETE FROM packets")
        return {'status': 'success', 'message': 'Database cleared successfully'}
    except Exception as e:
        return {'status': 'error', 'message': f'Failed to clear database: {str(e)}'}


# NEW: Add function to get packets with pagination
@eel.expose
@handle_errors
def get_packets_page(offset: int, limit: int) -> List[Dict[str, Any]]:
    """Get packets with pagination for infinite scroll"""
    try:
        rows = DatabaseManager.execute_query(
            "SELECT * FROM packets ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
            fetch_all=True
        )

        packets = []
        for row in rows or []:
            packet = {
                'id': row[0],
                'time': row[1],
                'src': row[2],
                'dst': row[3],
                'src_full': row[4],
                'dst_full': row[5],
                'proto': row[6],
                'domain': row[7],
                'info': row[8],
                'size': row[9],
                'src_port': row[10],
                'dst_port': row[11],
                'sensitive_data': json.loads(row[12]) if row[12] else []
            }
            packets.append(packet)

        return packets
    except Exception as e:
        return []


@eel.expose
@handle_errors
def register_user(username: str, password: str, activation_code: str) -> Dict[str, str]:
    """Enhanced user registration with proper validation and security"""

    # Input validation
    if not all([username, password, activation_code]):
        return {'status': 'error', 'message': 'All fields are required.'}

    if not SecurityManager.validate_input(username, "username"):
        return {'status': 'error',
                'message': 'Invalid username. Use 3-50 characters, letters, numbers, underscore, or dash only.'}

    if not SecurityManager.validate_input(password, "password"):
        return {'status': 'error', 'message': 'Password must be at least 8 characters long.'}

    if not SecurityManager.validate_input(activation_code, "activation_code"):
        return {'status': 'error', 'message': 'Invalid activation code format.'}

    try:
        # Check if username already exists
        existing_user = DatabaseManager.execute_query(
            "SELECT id FROM users WHERE username = ?",
            (username,),
            fetch_one=True
        )

        if existing_user:
            return {'status': 'error', 'message': 'Username already exists.'}

        # Generate machine ID and hash password
        machine_id = AuthenticationManager.get_machine_id()
        password_hash = AuthenticationManager.hash_password(password)

        # Insert new user
        DatabaseManager.execute_query(
            """INSERT INTO users (username, password_hash, salt, activation_code, machine_id) 
               VALUES (?, ?, ?, ?, ?)""",
            (username, password_hash, "", activation_code, machine_id)
        )

        return {'status': 'success', 'message': 'Registration successful! You can now log in.'}

    except Exception as e:
        return {'status': 'error', 'message': 'Registration failed. Please try again.'}


@eel.expose
@handle_errors
def login_user(username: str, password: str) -> Dict[str, str]:
    """Enhanced user login with rate limiting and security"""

    # Input validation
    if not all([username, password]):
        return {'status': 'error', 'message': 'All fields are required.'}

    if not SecurityManager.validate_input(username, "username"):
        return {'status': 'error', 'message': 'Invalid username format.'}

    # Check login attempt limits
    allowed, message = SecurityManager.is_login_allowed(username)
    if not allowed:
        return {'status': 'error', 'message': message}

    try:
        # Get user data
        user_data = DatabaseManager.execute_query(
            "SELECT password_hash, machine_id, is_active FROM users WHERE username = ?",
            (username,),
            fetch_one=True
        )

        if not user_data:
            SecurityManager.record_failed_login(username)
            return {'status': 'error', 'message': 'Invalid username or password.'}

        stored_password_hash, stored_machine_id, is_active = user_data

        # Check if account is active
        if not is_active:
            return {'status': 'error', 'message': 'Account is disabled.'}

        # Verify password
        if not AuthenticationManager.verify_password(password, stored_password_hash):
            SecurityManager.record_failed_login(username)
            return {'status': 'error', 'message': 'Invalid username or password.'}

        # Check machine ID
        current_machine_id = AuthenticationManager.get_machine_id()
        if stored_machine_id != current_machine_id:
            SecurityManager.record_failed_login(username)
            return {'status': 'error', 'message': 'This account is licensed to another computer.'}

        # Update last login time
        DatabaseManager.execute_query(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?",
            (username,)
        )

        # Clear failed login attempts
        SecurityManager.clear_login_attempts(username)

        return {'status': 'success', 'message': 'Login successful!'}

    except Exception as e:
        SecurityManager.record_failed_login(username)
        return {'status': 'error', 'message': 'Login failed. Please try again.'}


@eel.expose
@handle_errors
def get_interfaces() -> Dict[str, Dict[str, str]]:
    """Get network interfaces with enhanced error handling"""
    interfaces = {}
    try:
        if_stats = psutil.net_if_stats()
        scapy_ifaces = conf.ifaces.items()

        for guid, data in scapy_ifaces:
            try:
                status = 'down'
                if data.name in if_stats and hasattr(if_stats[data.name], 'isup'):
                    if if_stats[data.name].isup:
                        status = 'up'

                interfaces[guid] = {
                    'name': data.name,
                    'description': data.description or 'N/A',
                    'ip': data.ip or 'N/A',
                    'mac': data.mac or 'N/A',
                    'status': status
                }
            except Exception as e:
                continue

        return interfaces

    except Exception as e:
        error_msg = f"Error loading interfaces: {e}. Please run as administrator and install Npcap."
        eel.show_error(error_msg)
        return {}


@eel.expose
@handle_errors
def get_packet_details(packet_id: str) -> Optional[Dict[str, Any]]:
    """Get detailed packet information with thread safety"""
    try:
        with raw_packets_lock:
            if packet_id in raw_packets_store:
                packet = raw_packets_store[packet_id]
                analyzer = PacketAnalyzer()
                return analyzer.analyze_packet(packet, get_full_details=True)
        return None
    except Exception as e:
        return None


@eel.expose
@handle_errors
def start_sniffing(interface_guid: str, bpf_filter: str) -> Optional[Dict[str, str]]:
    """Start packet sniffing with enhanced validation and error handling"""
    global sniffer_thread

    with sniffer_lock:
        if sniffer_thread and sniffer_thread.is_alive():
            return {'status': 'error', 'message': 'Sniffing is already running'}

    # Validate inputs
    if not interface_guid or not SecurityManager.validate_input(interface_guid, "general"):
        return {'status': 'error', 'message': 'Invalid interface selected'}

    if bpf_filter and not SecurityManager.validate_input(bpf_filter, "general"):
        return {'status': 'error', 'message': 'Invalid BPF filter'}

    try:
        selected_interface_obj = conf.ifaces[interface_guid]
    except KeyError:
        error_msg = f"Error: Interface with ID '{interface_guid}' not found."
        eel.show_error(error_msg)
        return {'status': 'error', 'message': error_msg}

    try:
        # Clear old data with thread safety
        with raw_packets_lock:
            raw_packets_store.clear()
        with cache_lock:
            dns_cache.clear()
            reverse_dns_cache.clear()

        with sniffer_lock:
            sniffer_thread = SniffingThread(selected_interface_obj, bpf_filter)
            sniffer_thread.start()

        eel.update_sniff_status(True)
        return {'status': 'success', 'message': 'Sniffing started successfully'}

    except Exception as e:
        error_msg = f"Failed to start sniffing: {e}"
        return {'status': 'error', 'message': error_msg}


@eel.expose
@handle_errors
def stop_sniffing() -> bool:
    """Stop packet sniffing safely"""
    global sniffer_thread

    with sniffer_lock:
        if sniffer_thread and sniffer_thread.is_alive():
            sniffer_thread.stop()
            sniffer_thread.join(timeout=5)

            if sniffer_thread.is_alive():
                pass
            else:
                pass

            sniffer_thread = None

    return True


@eel.expose
@handle_errors
def show_save_dialog(file_types: List[List[str]]) -> str:
    """Show file save dialog with error handling"""
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        # Validate file types
        validated_types = []
        for file_type in file_types:
            if len(file_type) >= 2 and SecurityManager.validate_input(file_type[0], "general"):
                validated_types.append(file_type)

        if not validated_types:
            validated_types = [['All files', '*.*']]

        file_path = filedialog.asksaveasfilename(
            defaultextension=validated_types[0][1],
            filetypes=validated_types
        )
        root.destroy()

        return file_path if file_path else ""

    except Exception as e:
        return ""


@eel.expose
@handle_errors
def export_pcap(file_path: str, packet_ids: List[str]) -> Dict[str, str]:
    """Export packets to PCAP file with validation"""
    try:
        if not file_path or not SecurityManager.validate_input(file_path, "general"):
            return {'status': 'error', 'message': 'Invalid file path.'}

        if not packet_ids:
            return {'status': 'error', 'message': 'No packet IDs provided.'}

        # Validate packet IDs
        validated_ids = [pid for pid in packet_ids if SecurityManager.validate_input(str(pid), "general")]

        with raw_packets_lock:
            packets_to_save = [raw_packets_store[pid] for pid in validated_ids if pid in raw_packets_store]

        if not packets_to_save:
            return {'status': 'error', 'message': 'No valid packets to save.'}

        wrpcap(file_path, packets_to_save)
        return {'status': 'success', 'message': f'Successfully saved {len(packets_to_save)} packets.'}

    except Exception as e:
        return {'status': 'error', 'message': str(e)}


@eel.expose
@handle_errors
def export_single_pcap(file_path: str, packet_id: str) -> Dict[str, str]:
    """Export single packet to PCAP file with validation"""
    try:
        if not file_path or not SecurityManager.validate_input(file_path, "general"):
            return {'status': 'error', 'message': 'Invalid file path.'}

        if not packet_id or not SecurityManager.validate_input(str(packet_id), "general"):
            return {'status': 'error', 'message': 'Invalid packet ID.'}

        with raw_packets_lock:
            if packet_id in raw_packets_store:
                packet_to_save = raw_packets_store[packet_id]
                wrpcap(file_path, [packet_to_save])
                return {'status': 'success', 'message': f'Successfully saved packet {packet_id}.'}
            else:
                return {'status': 'error', 'message': 'Packet ID not found.'}

    except Exception as e:
        return {'status': 'error', 'message': str(e)}


@eel.expose
@handle_errors
def export_txt(file_path: str, content: str) -> Dict[str, str]:
    """Export text content to file with validation"""
    try:
        if not file_path or not SecurityManager.validate_input(file_path, "general"):
            return {'status': 'error', 'message': 'Invalid file path.'}

        if not content:
            return {'status': 'error', 'message': 'No content to export.'}

        # Sanitize content
        safe_content = content.replace('\x00', '')  # Remove null bytes

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(safe_content)

        return {'status': 'success', 'message': 'File saved successfully.'}

    except Exception as e:
        return {'status': 'error', 'message': str(e)}


def cleanup_resources():
    """Clean up resources on application exit"""
    try:
        stop_sniffing()

        # Clear caches
        with cache_lock:
            dns_cache.clear()
            reverse_dns_cache.clear()

        with raw_packets_lock:
            raw_packets_store.clear()

    except Exception as e:
        pass


def run_app():
    """Main application entry point with enhanced error handling"""
    try:
        # Initialize database
        DatabaseManager.init_database()

        # Define the web folder path relative to the root
        web_folder = os.path.join(BASE_DIR, 'web')
        print(f"Attempting to use web folder: {web_folder}")

        # Initialize eel with proper settings
        web_folder = resource_path('web')
        eel.init(web_folder)

        # Try different browser options to avoid gevent issues
        try:
            # First try Chrome in app mode with proper parameters
            eel.start('index.html',
                      size=(1200, 800),
                      port=0,
                      mode='chrome',
                      cmdline_args=['--app-mode', '--disable-web-security', '--allow-running-insecure-content'],
                      host='localhost',
                      block=True)

        except Exception as e:
            error_msg = f"Could not start application. Browser error: {str(e)}"
            print(error_msg)
            sys.exit(1)

    except Exception as e:
        print(f"Critical application error: {e}")
        input("Press Enter to continue...")
        sys.exit(1)
    finally:
        cleanup_resources()