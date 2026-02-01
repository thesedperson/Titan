# 🛡️ Titan - Ultimate Reconnaissance Tool

![Version](https://img.shields.io/badge/version-2.1-blue) ![Python](https://img.shields.io/badge/python-3.10%2B-yellow) ![License](https://img.shields.io/badge/license-MIT-green)

**Titan** is a high-performance, asynchronous vulnerability scanner and reconnaissance tool designed for modern penetration testers. Built with **speed** and **precision** in mind, it combines passive OSINT with active brute-forcing to uncover the attack surface of any target in minutes.

---

## 🚀 Features

### 🔥 **Speed & Performance**
- **AsyncIO Core**: Built on Python's `asyncio` and `aiohttp` for non-blocking, massively parallel execution.
- **Smart Concurrency**: Automatically adjusts threads/tasks (up to 100+) for maximum throughput.
- **Nmap Integration**: Optimized profiles (`-F` top 100 ports, `--min-rate 1000`) for lightning-fast port scanning.

### 🕵️ **Comprehensive Enumeration**
- **Subdomain Discovery**: Hybryd approach using passive sources (**crt.sh, HackerTarget, AlienVault**) and directory brute-forcing.
- **WAF Detection**: identifies generic WAFs (Cloudflare, AWS, etc.) and attempts **automatic bypass** (header tampering, UA rotation).
- **Directory & VHost Busting**: 
    - **Zero-Tolerance Noise Filter**: Smartly filters wildcard 403 pages to hide useless junk.
    - **Double Calibration**: Auto-calibrates against current server state to detect anomalies.
- **Tech Fingerprinting**: Identifies technologies (CMS, Server, Frameworks).
- **Cloud Enumeration**: Scans for open AWS S3 buckets.
- **Passive Recon**: Auto-fetches **Whois**, **SSL Certs**, and **Wayback Machine** archives.

### 🖥️ **Modern TUI (Terminal UI)**
- Real-time **Dashboard** powered by `rich`.
- Live "Attack Surface" tree finding.
- Split-panel view for logs, progress, and finding details.

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/thesedperson/Titan.git
   cd Titan
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **External Tools:**
   - **Nmap**: Required for port scanning.
     ```bash
     sudo apt install nmap
     ```

### 🔧 Troubleshooting Installation

If you encounter an "externally managed environment" error (common on generic Linux distros):

**Option 1: Use a Virtual Environment (Recommended)**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Option 2: Force System Install**
```bash
pip install -r requirements.txt --break-system-packages
```

---

## 🛠️ Usage

Simply run the script to enter the interactive menu:

```bash
python3 titan.py
```

### Scan Profiles
Titan offers 3 optimized scan profiles:

1.  **🤫 Quiet Mode**
    - Passive Recon ONLY (Whois, SSL, Headers, Passive Subdomains, Wayback).
    - No active brute-forcing or port scanning.
    - Completely stealthy.

2.  **⚡ Standard Mode (Recommended)**
    - All Quiet features +
    - **Port Scan**: Fast `-F` (Top 100 ports) + Version Detection.
    - **Dir/VHost Enum**: Optimized brute-forcing using `common.txt`.
    - **WAF**: Active detection & bypass.

3.  **🔥 Full Mode**
    - All Standard features +
    - **Port Scan**: Aggressive `-A` (Top 1000 ports + OS/Scripts).
    - **DNS**: Full AXFR zone transfer attempts.

---

## 📂 Project Structure

```
Titan/
├── titan.py            # Main entry point & TUI Engine
├── requirements.txt    # Python dependencies
├── reports/            # Auto-saved scan reports
└── modules/
    ├── dirrec.py       # Async Directory/VHost Brute-forcer
    ├── dns.py          # DNS Recon & AXFR
    ├── portscan.py     # Nmap Wrapper
    ├── subdom.py       # Passive Subdomain Enum
    ├── waf.py          # WAF Detector
    ├── ...             # Other specialized modules
```

## ⚠️ Disclaimer

This tool is for **educational and authorized security testing purposes only**. The author is not responsible for any misuse. Always obtain permission before scanning any target.