🛡️ FirewallSenior Enterprise
Personal Network Security & Firewall Monitor — v4.0.0
Show Image
Show Image
Show Image
Show Image
Show Image

A professional-grade personal firewall and network monitoring tool built in Python. Monitor all active connections in real time, detect threats using a built-in threat intelligence engine, block malicious IPs, and export security reports — all from a clean desktop GUI.


✨ Features

Real-time Connection Monitoring — continuously scans all active network connections using psutil
Threat Intelligence Engine — built-in database of known malicious IPs, C2 infrastructure, ransomware networks, and botnets
Risk Assessment — every connection is scored 0–100 based on IP reputation, port risk, and process behaviour
Suspicious Process Detection — flags high-risk Windows processes like powershell.exe, mshta.exe, certutil.exe, and more
IP Blocking — block any IP address directly via Windows Firewall (netsh) rules with one click
IP Unblocking — remove firewall rules for previously blocked addresses
Whitelist Support — trust local networks and known-safe addresses automatically
Security Alert Feed — colour-coded real-time alert log (Critical / High / Medium / Low / Info)
Threat Intelligence Dashboard — summary of blocked IPs, total alerts, critical incidents
Security Report Export — export full JSON reports of active connections and alerts
Persistent Storage — blocklist, whitelist, and alert history saved locally between sessions
Administrator Auto-Elevation — automatically requests UAC elevation on launch


🧱 Architecture
firewallsenior/
├── firewallsenior.py          ← Main application
├── data/
│   ├── blocklist.json         ← Persistent blocked IPs
│   ├── whitelist.json         ← Trusted IPs
│   └── alerts.json            ← Alert history
├── config/                    ← Reserved for future config
└── logs/
    └── firewallsenior_YYYYMMDD.log

⚙️ Requirements
RequirementDetailsOSWindows 10 / 11Python3.8 or higherPrivilegesAdministrator (UAC) requiredpsutilRecommended for full functionality

🚀 Installation
Step 1 — Clone the repository:
bashgit clone https://github.com/yourusername/firewallsenior.git
cd firewallsenior
Step 2 — Install dependencies:
bashpip install psutil
Step 3 — Run as Administrator:
bashpython firewallsenior.py

⚠️ The app will automatically request administrator privileges via UAC on launch. This is required for reading network connections and creating Windows Firewall rules.


📦 Build Standalone EXE
To share with others without requiring Python:
bashpip install pyinstaller
pyinstaller --onefile --windowed --name "FirewallSenior" firewallsenior.py
The executable will be in the dist/ folder.

🔍 How It Works
Threat Intelligence Engine
Every active connection is assessed against:
CheckDescriptionMalicious IP DatabaseKnown C2 servers, ransomware networks, APT infrastructurePort Risk MatrixPorts like 445 (SMB), 3389 (RDP), 23 (Telnet) are flaggedProcess RiskSuspicious Windows processes are scored higherConnection FrequencyUnusually high connection counts raise the risk scoreWhitelistLocal networks (192.168.x, 10.x, 127.x) and trusted DNS are auto-trusted
Risk Levels
ScoreLevelAction0–20🟢 NormalAllow21–50🟡 SuspiciousMonitor51–75🟠 High RiskAlert76–100🔴 CriticalAuto-block
Built-in Threat Database
Includes signatures for:

APT28 / APT29 C2 Infrastructure
Lazarus Group & Sandworm Team
LockBit / Conti / REvil Ransomware Networks
Emotet Botnet Infrastructure
TrickBot Banking Trojan


🖥️ Interface Guide
SectionDescriptionDashboardLive stats — active connections, packet rate, alerts, blocked IPs, uptimeConnection TableAll active connections with process, IP, port, risk level, and scoreAlert FeedReal-time colour-coded security eventsThreat IntelligenceSummary report of the current threat landscapeBlock / UnblockManually block or unblock any IP addressExport ReportSave a full JSON security report to the data folder

🔒 IP Blocking
When you block an IP (manually or via auto-block):

The IP is added to the persistent blocklist.json
A Windows Firewall rule is created via netsh for both inbound and outbound traffic
A critical alert is logged in the alert feed

To unblock, enter the IP in the block field and click Unblock — the firewall rule is removed automatically.

⚠️ Important Notes

Windows only — uses Windows-specific APIs (ctypes, netsh, psutil on Windows)
Administrator required — without elevation, firewall rules cannot be created or modified
Educational/Personal use — the threat database is a static snapshot; for production use, integrate a live threat feed (e.g. AbuseIPDB)
False positives — some legitimate software may trigger alerts; use the whitelist to suppress known-safe IPs


🛣️ Roadmap

 Live AbuseIPDB / VirusTotal API integration
 Packet-level inspection with scapy / pyshark
 Email / desktop notification alerts
 Automatic threat feed updates
 Traffic graphs and bandwidth monitoring


Built for personal cybersecurity monitoring and SOC analyst learning purposes.
