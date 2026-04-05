# 🛡️ FirewallSenior Enterprise
### Personal Network Security & Firewall Monitor — v4.0.0

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Admin](https://img.shields.io/badge/Requires-Administrator-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-4.0.0-orange?style=flat-square)

> A professional-grade personal firewall and network monitoring tool built in Python. Monitor all active connections in real time, detect threats using a built-in threat intelligence engine, block malicious IPs, and export security reports — all from a clean desktop GUI.

---

## 📸 Screenshot

> *Dashboard showing real-time connection monitoring, threat feed, and security statistics.*

---

## ✨ Features

- **Real-time Connection Monitoring** — continuously scans all active network connections using `psutil`
- **Threat Intelligence Engine** — built-in database of known malicious IPs, C2 infrastructure, ransomware networks, and botnets
- **Risk Assessment** — every connection is scored 0–100 based on IP reputation, port risk, and process behaviour
- **Suspicious Process Detection** — flags high-risk Windows processes like `powershell.exe`, `mshta.exe`, `certutil.exe`, and more
- **IP Blocking** — block any IP address directly via Windows Firewall (`netsh`) rules with one click
- **IP Unblocking** — remove firewall rules for previously blocked addresses
- **Whitelist Support** — trust local networks and known-safe addresses automatically
- **Security Alert Feed** — colour-coded real-time alert log (Critical / High / Medium / Low / Info)
- **Threat Intelligence Dashboard** — summary of blocked IPs, total alerts, critical incidents
- **Security Report Export** — export full JSON reports of active connections and alerts
- **Persistent Storage** — blocklist, whitelist, and alert history saved locally between sessions
- **Administrator Auto-Elevation** — automatically requests UAC elevation on launch

---

## ⚙️ Requirements

| Requirement | Details |
|---|---|
| OS | Windows 10 / 11 |
| Python | 3.8 or higher |
| Privileges | Administrator (UAC) required |
| psutil | Recommended for full functionality |

---

## 🚀 Installation

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/yourusername/firewallsenior.git
cd firewallsenior
```

**Step 2 — Install dependencies:**
```bash
pip install psutil
```

**Step 3 — Run as Administrator:**
```bash
python firewallsenior.py
```

> ⚠️ The app will automatically request administrator privileges via UAC on launch. This is required for reading network connections and creating Windows Firewall rules.

---

## 📦 Build Standalone EXE

To share with others without requiring Python:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "FirewallSenior" firewallsenior.py
```

The executable will be in the `dist/` folder.

---

## 🔍 How It Works

### Threat Intelligence Engine
Every active connection is assessed against:

| Check | Description |
|---|---|
| **Malicious IP Database** | Known C2 servers, ransomware networks, APT infrastructure |
| **Port Risk Matrix** | Ports like 445 (SMB), 3389 (RDP), 23 (Telnet) are flagged |
| **Process Risk** | Suspicious Windows processes are scored higher |
| **Connection Frequency** | Unusually high connection counts raise the risk score |
| **Whitelist** | Local networks (192.168.x, 10.x, 127.x) and trusted DNS are auto-trusted |

### Risk Levels

| Score | Level | Action |
|---|---|---|
| 0–20 | 🟢 Normal | Allow |
| 21–50 | 🟡 Suspicious | Monitor |
| 51–75 | 🟠 High Risk | Alert |
| 76–100 | 🔴 Critical | Auto-block |

### Built-in Threat Database
Includes signatures for:
- APT28 / APT29 C2 Infrastructure
- Lazarus Group & Sandworm Team
- LockBit / Conti / REvil Ransomware Networks
- Emotet Botnet Infrastructure
- TrickBot Banking Trojan

---

## 🖥️ Interface Guide

| Section | Description |
|---|---|
| **Dashboard** | Live stats — active connections, packet rate, alerts, blocked IPs, uptime |
| **Connection Table** | All active connections with process, IP, port, risk level, and score |
| **Alert Feed** | Real-time colour-coded security events |
| **Threat Intelligence** | Summary report of the current threat landscape |
| **Block / Unblock** | Manually block or unblock any IP address |
| **Export Report** | Save a full JSON security report to the data folder |

---

## 🔒 IP Blocking

When you block an IP (manually or via auto-block):

1. The IP is added to the persistent `blocklist.json`
2. A Windows Firewall rule is created via `netsh` for both inbound and outbound traffic
3. A critical alert is logged in the alert feed

To unblock, enter the IP in the block field and click **Unblock** — the firewall rule is removed automatically.

---

## ⚠️ Important Notes

- **Windows only** — uses Windows-specific APIs (`ctypes`, `netsh`, `psutil` on Windows)
- **Administrator required** — without elevation, firewall rules cannot be created or modified
- **Educational/Personal use** — the threat database is a static snapshot; for production use, integrate a live threat feed (e.g. AbuseIPDB)
- **False positives** — some legitimate software may trigger alerts; use the whitelist to suppress known-safe IPs

---

## 🛣️ Roadmap

- [ ] Live AbuseIPDB / VirusTotal API integration
- [ ] Packet-level inspection with `scapy` / `pyshark`
- [ ] Email / desktop notification alerts
- [ ] Automatic threat feed updates
- [ ] Traffic graphs and bandwidth monitoring
---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

##
Built for personal cybersecurity monitoring and SOC analyst learning purposes.
