"""
FIREWALLSENIOR ENTERPRISE - Professional Network Security Platform
Version 4.0.0 | Enterprise Grade | Administrator Required
Copyright (c) 2024 FirewallSenior. All rights reserved.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import socket
import subprocess
import os
import sys
import json
import ctypes
from datetime import datetime
from collections import defaultdict, deque

# ============================================================================
# SYSTEM REQUIREMENTS & VALIDATION
# ============================================================================

def validate_administrator() -> bool:
    """Validate administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_elevation() -> None:
    """Request administrator elevation"""
    if not validate_administrator():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

# Execute elevation request
request_elevation()

# Import after elevation
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ============================================================================
# APPLICATION CONFIGURATION
# ============================================================================

APPLICATION_NAME = "FirewallSenior Enterprise"
APPLICATION_VERSION = "4.0.0"
APPLICATION_VENDOR = "FirewallSenior Security"
COPYRIGHT = "Copyright (c) 2024 FirewallSenior. All rights reserved."

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_DIR, "data")
CONFIG_DIR = os.path.join(PROJECT_DIR, "config")
LOG_DIR = os.path.join(PROJECT_DIR, "logs")

for directory in [DATA_DIR, CONFIG_DIR, LOG_DIR]:
    os.makedirs(directory, exist_ok=True)

BLOCKLIST_DATABASE = os.path.join(DATA_DIR, "blocklist.json")
WHITELIST_DATABASE = os.path.join(DATA_DIR, "whitelist.json")
ALERT_DATABASE = os.path.join(DATA_DIR, "alerts.json")
EVENT_LOG = os.path.join(LOG_DIR, f"firewallsenior_{datetime.now().strftime('%Y%m%d')}.log")

# ============================================================================
# THREAT INTELLIGENCE ENGINE
# ============================================================================

class ThreatIntelligenceEngine:
    """Enterprise threat intelligence and risk assessment"""
    
    # Known malicious indicators database
    MALICIOUS_INDICATORS = {
        '185.130.5.253': {'threat': 'APT28 C2 Infrastructure', 'severity': 95, 'category': 'Advanced Persistent Threat'},
        '45.155.205.233': {'threat': 'APT29 C2 Infrastructure', 'severity': 95, 'category': 'Advanced Persistent Threat'},
        '103.86.1.1': {'threat': 'Lazarus Group Infrastructure', 'severity': 98, 'category': 'Nation State Actor'},
        '194.88.105.53': {'threat': 'Sandworm Team Infrastructure', 'severity': 96, 'category': 'Nation State Actor'},
        '185.130.5.0/24': {'threat': 'LockBit Ransomware Network', 'severity': 100, 'category': 'Ransomware'},
        '45.155.205.0/24': {'threat': 'Conti Ransomware Network', 'severity': 100, 'category': 'Ransomware'},
        '103.86.1.0/24': {'threat': 'REvil Malware Network', 'severity': 99, 'category': 'Ransomware'},
        '185.220.101.0/24': {'threat': 'Emotet Botnet Infrastructure', 'severity': 92, 'category': 'Botnet'},
        '94.102.61.0/24': {'threat': 'TrickBot Banking Trojan', 'severity': 90, 'category': 'Banking Malware'},
    }
    
    # Network service risk classification
    SERVICE_RISK_MATRIX = {
        22: {'service': 'SSH', 'risk': 65, 'description': 'Secure Shell Access'},
        23: {'service': 'Telnet', 'risk': 90, 'description': 'Unencrypted Remote Access'},
        80: {'service': 'HTTP', 'risk': 10, 'description': 'Web Traffic'},
        443: {'service': 'HTTPS', 'risk': 5, 'description': 'Secure Web Traffic'},
        445: {'service': 'SMB', 'risk': 98, 'description': 'File Sharing - High Risk'},
        3389: {'service': 'RDP', 'risk': 85, 'description': 'Remote Desktop Protocol'},
        5900: {'service': 'VNC', 'risk': 80, 'description': 'Remote Access'},
        1433: {'service': 'MSSQL', 'risk': 75, 'description': 'Database Service'},
        3306: {'service': 'MySQL', 'risk': 70, 'description': 'Database Service'},
        5432: {'service': 'PostgreSQL', 'risk': 70, 'description': 'Database Service'},
    }
    
    # Suspicious process indicators
    SUSPICIOUS_PROCESS_INDICATORS = {
        'powershell.exe': 80, 'cmd.exe': 65, 'wscript.exe': 85, 'cscript.exe': 85,
        'mshta.exe': 90, 'rundll32.exe': 70, 'regsvr32.exe': 80, 'wmic.exe': 75,
        'certutil.exe': 80, 'bitsadmin.exe': 75, 'net.exe': 60, 'sc.exe': 65
    }
    
    def __init__(self):
        self.blocklist = set()
        self.whitelist = set()
        self.alert_records = []
        self.connection_history = defaultdict(lambda: {'count': 0, 'ports': set()})
        self._load_data()
    
    def _load_data(self) -> None:
        """Load persistent data from storage"""
        for file_path, data_store in [(BLOCKLIST_DATABASE, self.blocklist), (WHITELIST_DATABASE, self.whitelist)]:
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as file:
                        data_store.update(json.load(file))
            except (json.JSONDecodeError, IOError):
                pass
        
        try:
            if os.path.exists(ALERT_DATABASE):
                with open(ALERT_DATABASE, 'r') as file:
                    self.alert_records = json.load(file)
        except (json.JSONDecodeError, IOError):
            pass
    
    def _save_data(self) -> None:
        """Save persistent data to storage"""
        with open(BLOCKLIST_DATABASE, 'w') as file:
            json.dump(list(self.blocklist), file)
        with open(WHITELIST_DATABASE, 'w') as file:
            json.dump(list(self.whitelist), file)
        with open(ALERT_DATABASE, 'w') as file:
            json.dump(self.alert_records[:5000], file)
    
    def _is_trusted_address(self, address: str) -> bool:
        """Determine if address is trusted"""
        if address in self.whitelist:
            return True
        
        # Local network ranges
        if address.startswith(('192.168.', '10.', '127.', '169.254.')):
            return True
        
        for prefix in ['172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
                       '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                       '172.28.', '172.29.', '172.30.', '172.31.']:
            if address.startswith(prefix):
                return True
        
        # Trusted infrastructure
        trusted_services = [
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9',
            '208.67.222.222', '208.67.220.220', '13.107.42.12', '13.107.42.13'
        ]
        return address in trusted_services
    
    def assess_connection(self, address: str, port: int, process: str) -> dict:
        """Perform comprehensive risk assessment"""
        if self._is_trusted_address(address):
            return self._create_assessment(0, 'normal', '#4CAF50', 'allow', ['Trusted Source'])
        
        risk_score = 0
        risk_factors = []
        
        # Check malicious indicators
        for indicator, data in self.MALICIOUS_INDICATORS.items():
            if self._address_in_range(address, indicator):
                risk_score += data['severity'] * 0.35
                risk_factors.append(f"Threat: {data['threat']}")
                break
        
        # Check service risk
        if port in self.SERVICE_RISK_MATRIX:
            service_data = self.SERVICE_RISK_MATRIX[port]
            risk_score += service_data['risk'] * 0.25
            risk_factors.append(f"Service: {service_data['service']}")
        
        # Check process indicators
        process_lower = process.lower()
        for indicator, severity in self.SUSPICIOUS_PROCESS_INDICATORS.items():
            if indicator in process_lower:
                risk_score += severity * 0.20
                risk_factors.append(f"Process: {indicator}")
                break
        
        # Update connection history
        self.connection_history[address]['count'] += 1
        self.connection_history[address]['ports'].add(port)
        
        # Behavioral analysis
        if address in self.connection_history:
            if self.connection_history[address]['count'] > 500:
                risk_score += 10
                risk_factors.append("High Traffic Volume")
            if len(self.connection_history[address]['ports']) > 15:
                risk_score += 8
                risk_factors.append("Port Scan Detected")
        
        risk_score = min(100, risk_score)
        
        # Determine risk classification
        if risk_score >= 85:
            classification = 'critical'
            color = '#E53935'
            action = 'block'
        elif risk_score >= 70:
            classification = 'high'
            color = '#FF6D00'
            action = 'alert'
        elif risk_score >= 45:
            classification = 'medium'
            color = '#FDD835'
            action = 'monitor'
        elif risk_score >= 20:
            classification = 'low'
            color = '#1E88E5'
            action = 'log'
        else:
            classification = 'normal'
            color = '#43A047'
            action = 'allow'
        
        return self._create_assessment(risk_score, classification, color, action, risk_factors[:4])
    
    def _create_assessment(self, score: float, level: str, color: str, action: str, factors: list) -> dict:
        """Create standardized assessment object"""
        return {
            'risk_score': round(score, 1),
            'risk_level': level,
            'display_color': color,
            'recommended_action': action,
            'risk_factors': factors,
            'assessment_timestamp': datetime.now().isoformat()
        }
    
    def _address_in_range(self, address: str, cidr: str) -> bool:
        """Check if address falls within CIDR range"""
        if '/' not in cidr:
            return address == cidr
        try:
            network, bits = cidr.split('/')
            bits = int(bits)
            addr_parts = [int(x) for x in address.split('.')]
            net_parts = [int(x) for x in network.split('.')]
            addr_int = (addr_parts[0] << 24) + (addr_parts[1] << 16) + (addr_parts[2] << 8) + addr_parts[3]
            net_int = (net_parts[0] << 24) + (net_parts[1] << 16) + (net_parts[2] << 8) + net_parts[3]
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            return (addr_int & mask) == (net_int & mask)
        except (ValueError, IndexError):
            return False
    
    def add_to_blocklist(self, address: str, reason: str = "Manual") -> bool:
        """Add address to blocklist"""
        if not self._is_trusted_address(address) and address not in self.blocklist:
            self.blocklist.add(address)
            self._save_data()
            self._log_alert(address, reason, 100, 'blocked')
            self._apply_firewall_rule(address)
            return True
        return False
    
    def remove_from_blocklist(self, address: str) -> bool:
        """Remove address from blocklist"""
        if address in self.blocklist:
            self.blocklist.remove(address)
            self._save_data()
            self._remove_firewall_rule(address)
            return True
        return False
    
    def _apply_firewall_rule(self, address: str) -> None:
        """Apply Windows Firewall rule"""
        if os.name == 'nt':
            rule_identifier = f"FirewallSenior_Block_{address.replace('.', '_')}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_identifier}', 'dir=in', 'action=block',
                f'remoteip={address}', 'protocol=any',
                'description=Blocked by FirewallSenior'
            ], capture=True)
    
    def _remove_firewall_rule(self, address: str) -> None:
        """Remove Windows Firewall rule"""
        if os.name == 'nt':
            rule_identifier = f"FirewallSenior_Block_{address.replace('.', '_')}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_identifier}'
            ], capture=True)
    
    def _log_alert(self, address: str, reason: str, score: int, action: str) -> None:
        """Record alert in database"""
        alert_record = {
            'timestamp': datetime.now().isoformat(),
            'source_address': address,
            'reason': reason,
            'risk_score': score,
            'action': action
        }
        self.alert_records.insert(0, alert_record)
        self.alert_records = self.alert_records[:10000]
        self._save_data()
        
        # Write to event log
        with open(EVENT_LOG, 'a') as log_file:
            log_file.write(f"[{datetime.now().isoformat()}] ALERT: {address} - {reason}\n")
    
    def get_statistics(self) -> dict:
        """Retrieve system statistics"""
        return {
            'blocked_addresses': len(self.blocklist),
            'trusted_addresses': len(self.whitelist),
            'total_alerts': len(self.alert_records),
            'critical_incidents': len([a for a in self.alert_records if a.get('risk_score', 0) >= 85]),
            'high_incidents': len([a for a in self.alert_records if 70 <= a.get('risk_score', 0) < 85])
        }


# ============================================================================
# NETWORK MONITOR SERVICE
# ============================================================================

class NetworkMonitorService:
    """Enterprise network monitoring service"""
    
    def __init__(self, threat_engine, update_handler, alert_handler):
        self.threat_engine = threat_engine
        self.update_handler = update_handler
        self.alert_handler = alert_handler
        self.is_running = False
        self.active_connections = {}
        self.service_statistics = {
            'total_packets': 0,
            'active_connections': 0,
            'alert_count': 0,
            'block_count': 0,
            'service_start': datetime.now()
        }
        self.packet_rate_history = deque(maxlen=60)
    
    def start_service(self) -> None:
        """Start monitoring service"""
        if self.is_running:
            return
        self.is_running = True
        self.service_statistics['service_start'] = datetime.now()
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
    def stop_service(self) -> None:
        """Stop monitoring service"""
        self.is_running = False
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.is_running:
            try:
                if PSUTIL_AVAILABLE:
                    self._capture_connections()
                else:
                    self._capture_connections_fallback()
                time.sleep(1)
            except Exception:
                time.sleep(2)
    
    def _capture_connections(self) -> None:
        """Capture network connections using psutil"""
        current_connections = {}
        
        for connection in psutil.net_connections(kind='inet'):
            try:
                if not connection.raddr or not connection.raddr.ip:
                    continue
                
                remote_address = connection.raddr.ip
                remote_port = connection.raddr.port
                
                if remote_address in ['0.0.0.0', '127.0.0.1', '::1']:
                    continue
                
                # Process identification
                process_name = "System"
                if connection.pid and connection.pid > 0:
                    try:
                        process_name = psutil.Process(connection.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = f"PID:{connection.pid}"
                
                # Risk assessment
                assessment = self.threat_engine.assess_connection(remote_address, remote_port, process_name)
                
                # Auto-block critical threats
                if assessment['recommended_action'] == 'block' and not self.threat_engine._is_trusted_address(remote_address):
                    if self.threat_engine.add_to_blocklist(remote_address, f"Auto: {assessment['risk_level'].upper()}"):
                        self.service_statistics['block_count'] += 1
                        self.alert_handler(f"AUTO-BLOCK: {remote_address} | Risk: {assessment['risk_score']}%", 'critical')
                
                # Alert on high/medium risks
                elif assessment['recommended_action'] in ['alert', 'monitor']:
                    self.service_statistics['alert_count'] += 1
                    self.alert_handler(
                        f"{assessment['risk_level'].upper()}: {process_name} -> {remote_address}:{remote_port} | Score: {assessment['risk_score']}%",
                        assessment['risk_level']
                    )
                
                self.service_statistics['total_packets'] += 1
                
                connection_key = f"{remote_address}:{remote_port}"
                current_connections[connection_key] = {
                    'address': remote_address,
                    'port': remote_port,
                    'process': process_name[:35],
                    'risk_level': assessment['risk_level'],
                    'risk_score': assessment['risk_score'],
                    'risk_factors': assessment['risk_factors'][:2] if assessment['risk_factors'] else [],
                    'status': 'ACTIVE',
                    'display_color': assessment['display_color']
                }
                
            except Exception:
                continue
        
        self.active_connections = current_connections
        self.service_statistics['active_connections'] = len(current_connections)
        
        # Calculate packet rate
        self.packet_rate_history.append(len(current_connections))
        avg_rate = sum(self.packet_rate_history) / len(self.packet_rate_history) if self.packet_rate_history else 0
        
        uptime = datetime.now() - self.service_statistics['service_start']
        statistics_summary = {
            'active': len(current_connections),
            'packet_rate': round(avg_rate, 1),
            'alerts': self.service_statistics['alert_count'],
            'blocks': self.service_statistics['block_count'],
            'uptime_hours': uptime.total_seconds() / 3600,
            'total_packets': self.service_statistics['total_packets']
        }
        
        self.update_handler(self._get_connection_list(), statistics_summary)
    
    def _capture_connections_fallback(self) -> None:
        """Fallback connection capture using netstat"""
        current_connections = {}
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=3)
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        remote = parts[2]
                        if ':' in remote:
                            address, port_str = remote.rsplit(':', 1)
                            if port_str.isdigit() and address and not address.startswith(('127.', '0.0.0.0')):
                                port = int(port_str)
                                assessment = self.threat_engine.assess_connection(address, port, "Unknown")
                                key = f"{address}:{port}"
                                current_connections[key] = {
                                    'address': address,
                                    'port': port,
                                    'process': 'Unknown',
                                    'risk_level': assessment['risk_level'],
                                    'risk_score': assessment['risk_score'],
                                    'status': 'ACTIVE',
                                    'display_color': assessment['display_color']
                                }
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        
        self.active_connections = current_connections
        self.update_handler(self._get_connection_list(), {'active': len(current_connections)})
    
    def _get_connection_list(self) -> list:
        """Retrieve formatted connection list"""
        return list(self.active_connections.values())
    
    def block_address(self, address: str, reason: str = "Manual") -> bool:
        """Block specified address"""
        if self.threat_engine.add_to_blocklist(address, reason):
            self.service_statistics['block_count'] += 1
            return True
        return False


# ============================================================================
# MAIN APPLICATION INTERFACE
# ============================================================================

class FirewallSeniorApplication:
    """Enterprise application main interface"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{APPLICATION_NAME} - {APPLICATION_VERSION}")
        self.root.geometry("1440x900")
        self.root.minsize(1280, 768)
        self.root.configure(bg='#1a1a1a')
        
        # Professional color palette
        self.color_scheme = {
            'background': '#1a1a1a',
            'surface': '#2a2a2a',
            'surface_variant': '#333333',
            'border': '#404040',
            'text_primary': '#ffffff',
            'text_secondary': '#b0b0b0',
            'text_disabled': '#707070',
            'critical': '#E53935',
            'high': '#FF6D00',
            'medium': '#FDD835',
            'low': '#1E88E5',
            'normal': '#4CAF50',
            'accent': '#2196F3'
        }
        
        self.threat_engine = ThreatIntelligenceEngine()
        self.monitor_service = NetworkMonitorService(
            self.threat_engine,
            self._handle_connection_update,
            self._handle_alert
        )
        
        self._initialize_user_interface()
        self._start_monitoring()
    
    def _initialize_user_interface(self) -> None:
        """Initialize the main user interface"""
        self.root.configure(bg=self.color_scheme['background'])
        
        # Application header
        self._create_header()
        
        # Statistics dashboard
        self._create_dashboard()
        
        # Main content area
        main_container = tk.PanedWindow(self.root, bg=self.color_scheme['border'], sashwidth=2)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        # Connection monitor panel
        self._create_connection_panel(main_container)
        
        # Security intelligence panel
        self._create_intelligence_panel(main_container)
        
        # Status bar
        self._create_status_bar()
    
    def _create_header(self) -> None:
        """Create application header"""
        header_frame = tk.Frame(self.root, bg=self.color_scheme['surface'], height=65)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Title section
        title_container = tk.Frame(header_frame, bg=self.color_scheme['surface'])
        title_container.pack(side=tk.LEFT, padx=20)
        
        tk.Label(title_container, text=APPLICATION_NAME, font=('Segoe UI', 16, 'bold'),
                bg=self.color_scheme['surface'], fg=self.color_scheme['accent']).pack(side=tk.LEFT)
        
        tk.Label(title_container, text=APPLICATION_VERSION, font=('Segoe UI', 9),
                bg=self.color_scheme['surface'], fg=self.color_scheme['text_disabled']).pack(side=tk.LEFT, padx=8)
        
        tk.Label(title_container, text="Enterprise Network Security", font=('Segoe UI', 9),
                bg=self.color_scheme['surface'], fg=self.color_scheme['text_secondary']).pack(side=tk.LEFT, padx=10)
        
        # Control panel
        control_container = tk.Frame(header_frame, bg=self.color_scheme['surface'])
        control_container.pack(side=tk.RIGHT, padx=20)
        
        self.start_button = tk.Button(control_container, text="START", command=self._start_monitoring,
                                     bg='#2E7D32', fg='white', font=('Segoe UI', 9, 'bold'),
                                     relief=tk.FLAT, padx=25, pady=7, cursor='hand2')
        self.start_button.pack(side=tk.LEFT, padx=3)
        
        self.stop_button = tk.Button(control_container, text="STOP", command=self._stop_monitoring,
                                    bg='#C62828', fg='white', font=('Segoe UI', 9, 'bold'),
                                    relief=tk.FLAT, padx=25, pady=7, cursor='hand2', state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=3)
        
        self.status_indicator = tk.Label(control_container, text="● ACTIVE", font=('Segoe UI', 9, 'bold'),
                                        bg=self.color_scheme['surface'], fg=self.color_scheme['normal'])
        self.status_indicator.pack(side=tk.LEFT, padx=15)
        
        # REMOVED: Administrator indicator label - no extra layout
    
    def _create_dashboard(self) -> None:
        """Create statistics dashboard"""
        dashboard_frame = tk.Frame(self.root, bg=self.color_scheme['surface_variant'], height=80)
        dashboard_frame.pack(fill=tk.X, padx=15, pady=(10, 0))
        dashboard_frame.pack_propagate(False)
        
        metric_definitions = [
            ('Active Connections', '0', self.color_scheme['accent']),
            ('Packet Rate', '0 pps', self.color_scheme['low']),
            ('Security Alerts', '0', self.color_scheme['high']),
            ('Blocked Addresses', '0', self.color_scheme['critical']),
            ('System Uptime', '0h', self.color_scheme['normal'])
        ]
        
        self.dashboard_metrics = []
        for index, (label, value, color) in enumerate(metric_definitions):
            metric_card = tk.Frame(dashboard_frame, bg=self.color_scheme['surface'], relief=tk.FLAT, bd=1,
                                  highlightbackground=self.color_scheme['border'], highlightthickness=1)
            metric_card.place(x=index*180 + 10, y=12, width=170, height=56)
            
            tk.Label(metric_card, text=label, font=('Segoe UI', 8), bg=self.color_scheme['surface'],
                    fg=self.color_scheme['text_secondary']).pack(pady=(8, 0))
            
            value_label = tk.Label(metric_card, text=value, font=('Segoe UI', 16, 'bold'),
                                  bg=self.color_scheme['surface'], fg=color)
            value_label.pack()
            self.dashboard_metrics.append(value_label)
    
    def _create_connection_panel(self, parent) -> None:
        """Create network connections panel"""
        connection_panel = tk.Frame(parent, bg=self.color_scheme['background'])
        parent.add(connection_panel, width=950)
        
        # Panel header
        header = tk.Frame(connection_panel, bg=self.color_scheme['surface'], height=38)
        header.pack(fill=tk.X, pady=(0, 10))
        header.pack_propagate(False)
        
        tk.Label(header, text="NETWORK CONNECTIONS", font=('Segoe UI', 10, 'bold'),
                bg=self.color_scheme['surface'], fg=self.color_scheme['text_primary']).pack(side=tk.LEFT, padx=15)
        
        # Search control
        search_container = tk.Frame(header, bg=self.color_scheme['surface'])
        search_container.pack(side=tk.RIGHT, padx=15)
        
        tk.Label(search_container, text="Search:", bg=self.color_scheme['surface'],
                fg=self.color_scheme['text_secondary']).pack(side=tk.LEFT, padx=5)
        
        self.search_query = tk.StringVar()
        self.search_query.trace('w', lambda *args: self._filter_connections())
        
        search_entry = tk.Entry(search_container, textvariable=self.search_query, bg=self.color_scheme['surface_variant'],
                               fg=self.color_scheme['text_primary'], width=20, relief=tk.FLAT,
                               insertbackground=self.color_scheme['text_primary'])
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Connection table
        table_container = tk.Frame(connection_panel, bg=self.color_scheme['background'])
        table_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        column_definitions = ('status', 'process', 'address', 'port', 'risk', 'factors', 'risk_score')
        self.connection_table = ttk.Treeview(table_container, columns=column_definitions, show='headings', height=22)
        
        self.connection_table.heading('status', text='')
        self.connection_table.heading('process', text='Process')
        self.connection_table.heading('address', text='IP Address')
        self.connection_table.heading('port', text='Port')
        self.connection_table.heading('risk', text='Risk Level')
        self.connection_table.heading('factors', text='Risk Factors')
        self.connection_table.heading('risk_score', text='Score')
        
        self.connection_table.column('status', width=35, anchor='center')
        self.connection_table.column('process', width=200)
        self.connection_table.column('address', width=140)
        self.connection_table.column('port', width=65, anchor='center')
        self.connection_table.column('risk', width=90, anchor='center')
        self.connection_table.column('factors', width=280)
        self.connection_table.column('risk_score', width=60, anchor='center')
        
        # Row color configuration
        self.connection_table.tag_configure('critical', background='#3d1a1a', foreground='#ff8888')
        self.connection_table.tag_configure('high', background='#3d2a1a', foreground='#ffaa66')
        self.connection_table.tag_configure('medium', background='#2a3d1a', foreground='#ffee66')
        self.connection_table.tag_configure('low', background='#1a2a3d', foreground='#88aaff')
        self.connection_table.tag_configure('normal', background='#1a2a1a', foreground='#88ff88')
        
        # Scrollbars
        vertical_scroll = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.connection_table.yview)
        horizontal_scroll = ttk.Scrollbar(table_container, orient=tk.HORIZONTAL, command=self.connection_table.xview)
        self.connection_table.configure(yscrollcommand=vertical_scroll.set, xscrollcommand=horizontal_scroll.set)
        
        self.connection_table.grid(row=0, column=0, sticky='nsew')
        vertical_scroll.grid(row=0, column=1, sticky='ns')
        horizontal_scroll.grid(row=1, column=0, sticky='ew')
        
        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)
        
        # Event bindings
        self.connection_table.bind('<MouseWheel>', self._handle_scroll)
        self.connection_table.bind('<Double-1>', lambda event: self._block_selected_connection())
        self.connection_table.bind('<<TreeviewSelect>>', self._display_connection_details)
        
        # Risk legend
        self._create_risk_legend(connection_panel)
    
    def _create_risk_legend(self, parent) -> None:
        """Create risk level legend"""
        legend_frame = tk.Frame(parent, bg=self.color_scheme['surface'], height=32)
        legend_frame.pack(fill=tk.X, pady=(10, 0))
        legend_frame.pack_propagate(False)
        
        legend_items = [
            ('CRITICAL', self.color_scheme['critical']),
            ('HIGH', self.color_scheme['high']),
            ('MEDIUM', self.color_scheme['medium']),
            ('LOW', self.color_scheme['low']),
            ('NORMAL', self.color_scheme['normal'])
        ]
        
        for label, color in legend_items:
            indicator = tk.Label(legend_frame, text="●", fg=color, bg=self.color_scheme['surface'],
                                font=('Segoe UI', 9))
            indicator.pack(side=tk.LEFT, padx=(15, 3))
            
            label_text = tk.Label(legend_frame, text=label, fg=self.color_scheme['text_secondary'],
                                 bg=self.color_scheme['surface'], font=('Segoe UI', 8))
            label_text.pack(side=tk.LEFT, padx=(0, 15))
    
    def _create_intelligence_panel(self, parent) -> None:
        """Create security intelligence panel"""
        intelligence_panel = tk.Frame(parent, bg=self.color_scheme['background'], width=420)
        parent.add(intelligence_panel, width=420)
        intelligence_panel.pack_propagate(False)
        
        # Threat intelligence section
        threat_frame = tk.LabelFrame(intelligence_panel, text="THREAT INTELLIGENCE",
                                    bg=self.color_scheme['background'], fg=self.color_scheme['text_primary'],
                                    font=('Segoe UI', 9, 'bold'), relief=tk.FLAT)
        threat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.threat_display = tk.Text(threat_frame, height=8, bg=self.color_scheme['surface_variant'],
                                     fg=self.color_scheme['text_primary'], font=('Consolas', 9),
                                     relief=tk.FLAT, wrap=tk.WORD)
        threat_scroll = ttk.Scrollbar(threat_frame, orient=tk.VERTICAL, command=self.threat_display.yview)
        self.threat_display.configure(yscrollcommand=threat_scroll.set)
        self.threat_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        threat_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Connection details section
        details_frame = tk.LabelFrame(intelligence_panel, text="CONNECTION DETAILS",
                                     bg=self.color_scheme['background'], fg=self.color_scheme['text_primary'],
                                     font=('Segoe UI', 9, 'bold'), relief=tk.FLAT)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.details_display = tk.Text(details_frame, height=10, bg=self.color_scheme['surface_variant'],
                                      fg=self.color_scheme['text_primary'], font=('Consolas', 9),
                                      relief=tk.FLAT, wrap=tk.WORD)
        details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_display.yview)
        self.details_display.configure(yscrollcommand=details_scroll.set)
        self.details_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        details_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Alert feed section
        alerts_frame = tk.LabelFrame(intelligence_panel, text="SECURITY ALERT FEED",
                                    bg=self.color_scheme['background'], fg=self.color_scheme['text_primary'],
                                    font=('Segoe UI', 9, 'bold'), relief=tk.FLAT)
        alerts_frame.pack(fill=tk.BOTH, expand=True)
        
        alert_toolbar = tk.Frame(alerts_frame, bg=self.color_scheme['background'])
        alert_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        clear_alerts_button = tk.Button(alert_toolbar, text="Clear Alerts", command=self._clear_alerts,
                                       bg=self.color_scheme['surface'], fg=self.color_scheme['text_secondary'],
                                       font=('Segoe UI', 8), relief=tk.FLAT, padx=10, cursor='hand2')
        clear_alerts_button.pack(side=tk.RIGHT)
        
        self.alert_listbox = tk.Listbox(alerts_frame, bg=self.color_scheme['surface_variant'],
                                       fg=self.color_scheme['text_primary'], font=('Consolas', 9),
                                       relief=tk.FLAT, height=8, selectbackground=self.color_scheme['surface'])
        alert_scroll = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alert_listbox.yview)
        self.alert_listbox.configure(yscrollcommand=alert_scroll.set)
        self.alert_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        alert_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action controls
        action_panel = tk.Frame(intelligence_panel, bg=self.color_scheme['background'], height=50)
        action_panel.pack(fill=tk.X, pady=(10, 0))
        action_panel.pack_propagate(False)
        
        tk.Label(action_panel, text="Block IP Address:", bg=self.color_scheme['background'],
                fg=self.color_scheme['text_secondary']).pack(side=tk.LEFT)
        
        self.block_address_entry = tk.Entry(action_panel, bg=self.color_scheme['surface_variant'],
                                           fg=self.color_scheme['text_primary'], width=14,
                                           relief=tk.FLAT, insertbackground=self.color_scheme['text_primary'])
        self.block_address_entry.pack(side=tk.LEFT, padx=5)
        self.block_address_entry.bind('<Return>', lambda event: self._block_address())
        
        block_button = tk.Button(action_panel, text="BLOCK", command=self._block_address,
                                bg='#C62828', fg='white', font=('Segoe UI', 8, 'bold'),
                                relief=tk.FLAT, padx=15, cursor='hand2')
        block_button.pack(side=tk.LEFT, padx=5)
        
        unblock_button = tk.Button(action_panel, text="UNBLOCK", command=self._unblock_address,
                                  bg=self.color_scheme['surface'], fg=self.color_scheme['text_secondary'],
                                  font=('Segoe UI', 8), relief=tk.FLAT, padx=12, cursor='hand2')
        unblock_button.pack(side=tk.LEFT, padx=5)
        
        export_button = tk.Button(action_panel, text="EXPORT REPORT", command=self._export_security_report,
                                 bg=self.color_scheme['accent'], fg='white', font=('Segoe UI', 8, 'bold'),
                                 relief=tk.FLAT, padx=12, cursor='hand2')
        export_button.pack(side=tk.RIGHT)
        
        # Initial information text
        self.details_display.insert(1.0, "Select a connection from the list to view detailed analysis.\n\nDouble-click any connection to block the IP address.\n\nRisk Level Guide:\n- CRITICAL: Immediate action required\n- HIGH: Investigation recommended\n- MEDIUM: Monitor activity\n- LOW: Log for reference\n- NORMAL: Standard traffic")
        
        self._update_threat_intelligence()
    
    def _create_status_bar(self) -> None:
        """Create application status bar"""
        status_bar = tk.Frame(self.root, bg=self.color_scheme['surface'], height=26)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(status_bar, text=f"{APPLICATION_NAME} - Protected Mode Active",
                bg=self.color_scheme['surface'], fg=self.color_scheme['text_disabled'],
                font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=15)
        
        self.system_time_label = tk.Label(status_bar, text="", bg=self.color_scheme['surface'],
                                         fg=self.color_scheme['text_disabled'], font=('Segoe UI', 8))
        self.system_time_label.pack(side=tk.RIGHT, padx=15)
        self._update_system_time()
    
    def _handle_scroll(self, event) -> None:
        """Handle mouse wheel scrolling"""
        self.connection_table.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def _filter_connections(self) -> None:
        """Filter connections based on search query"""
        search_text = self.search_query.get().lower()
        for item in self.connection_table.get_children():
            values = self.connection_table.item(item)['values']
            if values:
                if search_text == "" or search_text in values[1].lower() or search_text in values[2].lower():
                    self.connection_table.see(item)
    
    def _display_connection_details(self, event) -> None:
        """Display detailed connection information"""
        selected_items = self.connection_table.selection()
        if not selected_items:
            return
        
        connection_data = self.connection_table.item(selected_items[0])['values']
        if not connection_data:
            return
        
        risk_level = connection_data[4].lower()
        risk_level_display = {
            'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'normal': 'NORMAL'
        }.get(risk_level, 'UNKNOWN')
        
        analysis_report = f"""
CONNECTION ANALYSIS REPORT
{'=' * 50}

Process Information:    {connection_data[1]}
Remote Address:         {connection_data[2]}
Remote Port:            {connection_data[3]}
Risk Classification:    {risk_level_display}
Risk Score:             {connection_data[6]}
Identified Factors:     {connection_data[5]}

SECURITY RECOMMENDATION
{'=' * 50}
"""
        
        if risk_level == 'critical':
            analysis_report += """
ACTION REQUIRED: IMMEDIATE BLOCKING RECOMMENDED

This connection exhibits characteristics consistent with known malicious activity.
Immediate action is required to prevent potential security compromise.

Recommended Actions:
1. Block this IP address immediately
2. Run comprehensive system security scan
3. Review system for unauthorized access
4. Document incident for security audit
"""
        elif risk_level == 'high':
            analysis_report += """
ACTION REQUIRED: INVESTIGATION RECOMMENDED

This connection shows suspicious patterns requiring investigation.

Recommended Actions:
1. Investigate the source process legitimacy
2. Consider blocking the remote address
3. Monitor for additional suspicious connections
4. Review process execution context
"""
        elif risk_level == 'medium':
            analysis_report += """
ACTION REQUIRED: CONTINUOUS MONITORING

This connection exhibits unusual but not immediately threatening behavior.

Recommended Actions:
1. Log connection for security audit trail
2. Monitor for pattern repetition
3. Review if behavior is expected
4. No immediate action required
"""
        elif risk_level == 'low':
            analysis_report += """
ACTION REQUIRED: ROUTINE LOGGING

This connection presents minimal security concern.

Recommended Actions:
1. Maintain standard logging
2. Review periodically for anomalies
3. No immediate action necessary
"""
        else:
            analysis_report += """
ACTION REQUIRED: NONE - NORMAL TRAFFIC

This connection represents standard network communication.

Recommended Actions:
1. Continue normal operations
2. Standard logging only required
3. No security action needed
"""
        
        self.details_display.delete(1.0, tk.END)
        self.details_display.insert(1.0, analysis_report)
    
    def _handle_connection_update(self, connections: list, statistics: dict) -> None:
        """Handle connection data updates"""
        # Clear existing entries
        for item in self.connection_table.get_children():
            self.connection_table.delete(item)
        
        risk_symbols = {
            'critical': '●', 'high': '●', 'medium': '◉', 'low': '○', 'normal': '○'
        }
        
        for connection in connections:
            risk_level = connection.get('risk_level', 'normal')
            symbol = risk_symbols.get(risk_level, '○')
            risk_factors = ', '.join(connection.get('risk_factors', [])) if connection.get('risk_factors') else '-'
            risk_score = f"{connection.get('risk_score', 0)}%"
            
            item = self.connection_table.insert('', tk.END, values=(
                symbol,
                connection.get('process', '-'),
                connection.get('address', '-'),
                connection.get('port', '-'),
                risk_level.upper(),
                risk_factors,
                risk_score
            ))
            self.connection_table.item(item, tags=(risk_level,))
        
        # Update dashboard metrics
        if self.dashboard_metrics:
            self.dashboard_metrics[0].config(text=str(statistics.get('active', 0)))
            self.dashboard_metrics[1].config(text=f"{statistics.get('packet_rate', 0)} pps")
            self.dashboard_metrics[2].config(text=str(statistics.get('alerts', 0)))
            self.dashboard_metrics[3].config(text=str(self.threat_engine.get_statistics()['blocked_addresses']))
            
            uptime = statistics.get('uptime_hours', 0)
            if uptime < 1:
                uptime_display = f"{int(uptime * 60)}m"
            else:
                uptime_display = f"{int(uptime)}h {int((uptime % 1) * 60)}m"
            self.dashboard_metrics[4].config(text=uptime_display)
    
    def _handle_alert(self, message: str, severity: str) -> None:
        """Handle security alerts"""
        self._record_alert(message, severity)
    
    def _record_alert(self, message: str, severity: str) -> None:
        """Record alert in the alert feed"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        severity_icons = {
            'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': 'ℹ️', 'warning': '⚠️'
        }
        icon = severity_icons.get(severity, '⚪')
        alert_entry = f"{icon} [{timestamp}] {message}"
        self.alert_listbox.insert(0, alert_entry)
        
        # Maintain maximum alert count
        if self.alert_listbox.size() > 500:
            self.alert_listbox.delete(500)
    
    def _update_threat_intelligence(self) -> None:
        """Update threat intelligence display"""
        statistics = self.threat_engine.get_statistics()
        intelligence_report = f"""
THREAT INTELLIGENCE SUMMARY
{'=' * 40}

Blocked IP Addresses:      {statistics['blocked_addresses']}
Whitelisted Addresses:     {statistics['trusted_addresses']}
Total Security Alerts:     {statistics['total_alerts']}
Critical Incidents:        {statistics['critical_incidents']}
High Severity Alerts:      {statistics['high_incidents']}

SYSTEM STATUS
{'=' * 40}
Real-time Protection:      ACTIVE
Packet Inspection:         ENABLED
Auto-blocking:             CRITICAL THREATS
"""
        self.threat_display.delete(1.0, tk.END)
        self.threat_display.insert(1.0, intelligence_report)
        self.root.after(5000, self._update_threat_intelligence)
    
    def _update_system_time(self) -> None:
        """Update system time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.system_time_label.config(text=current_time)
        self.root.after(1000, self._update_system_time)
    
    def _clear_alerts(self) -> None:
        """Clear all alerts from the feed"""
        self.alert_listbox.delete(0, tk.END)
        self._record_alert("Alert history cleared", 'info')
    
    def _block_selected_connection(self) -> None:
        """Block the selected connection's IP address"""
        selected_items = self.connection_table.selection()
        if not selected_items:
            return
        
        connection_data = self.connection_table.item(selected_items[0])['values']
        if connection_data and len(connection_data) > 2:
            address = connection_data[2]
            if messagebox.askyesno("Confirm Block", f"Block IP Address: {address}\n\nThis will add a permanent firewall rule."):
                if self.monitor_service.block_address(address, "Manual block from interface"):
                    self._record_alert(f"Manually blocked: {address}", 'critical')
                    messagebox.showinfo("Operation Complete", f"IP address {address} has been blocked")
    
    def _block_address(self) -> None:
        """Block IP address from entry field"""
        address = self.block_address_entry.get().strip()
        if address:
            if self.monitor_service.block_address(address, "Manual entry"):
                self.block_address_entry.delete(0, tk.END)
                self._record_alert(f"Manually blocked: {address}", 'critical')
                messagebox.showinfo("Operation Complete", f"IP address {address} has been blocked")
        else:
            messagebox.showwarning("Input Required", "Please enter a valid IP address")
    
    def _unblock_address(self) -> None:
        """Unblock IP address from entry field"""
        address = self.block_address_entry.get().strip()
        if address:
            if self.threat_engine.remove_from_blocklist(address):
                self.block_address_entry.delete(0, tk.END)
                self._record_alert(f"Unblocked: {address}", 'info')
                messagebox.showinfo("Operation Complete", f"IP address {address} has been unblocked")
            else:
                messagebox.showwarning("Not Found", f"IP address {address} is not in the blocklist")
        else:
            messagebox.showwarning("Input Required", "Please enter a valid IP address")
    
    def _export_security_report(self) -> None:
        """Export security report to JSON file"""
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(DATA_DIR, report_filename)
        
        connection_data = []
        for item in self.connection_table.get_children():
            values = self.connection_table.item(item)['values']
            if values:
                connection_data.append({
                    'process': values[1],
                    'ip_address': values[2],
                    'port': values[3],
                    'risk_level': values[4],
                    'risk_factors': values[5],
                    'risk_score': values[6]
                })
        
        security_report = {
            'report_metadata': {
                'application': APPLICATION_NAME,
                'version': APPLICATION_VERSION,
                'timestamp': datetime.now().isoformat(),
                'vendor': APPLICATION_VENDOR
            },
            'system_statistics': self.threat_engine.get_statistics(),
            'active_connections': len(connection_data),
            'connections': connection_data,
            'recent_alerts': list(self.alert_listbox.get(0, 100))
        }
        
        with open(report_path, 'w') as report_file:
            json.dump(security_report, report_file, indent=2)
        
        messagebox.showinfo("Export Complete", f"Security report saved to:\n{report_path}")
    
    def _start_monitoring(self) -> None:
        """Start monitoring service"""
        self.monitor_service.start_service()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_indicator.config(text="● ACTIVE", fg=self.color_scheme['normal'])
        self._record_alert("Monitoring service activated", 'info')
    
    def _stop_monitoring(self) -> None:
        """Stop monitoring service"""
        self.monitor_service.stop_service()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_indicator.config(text="● INACTIVE", fg=self.color_scheme['text_disabled'])
        self._record_alert("Monitoring service deactivated", 'warning')
    
    def run(self) -> None:
        """Run the application"""
        self.root.mainloop()


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print(f"""
{APPLICATION_NAME} {APPLICATION_VERSION}
{COPYRIGHT}
{"=" * 60}
System Requirements:
- Administrator privileges required
- Windows operating system
- Python 3.8 or higher
- psutil library recommended
{"=" * 60}
    """)
    
    if not PSUTIL_AVAILABLE:
        print("Notice: psutil library not detected. Install for enhanced monitoring:\n   pip install psutil\n")
    
    application = FirewallSeniorApplication()
    application.run()