# 🔱 Nmap Cascade

**Intelligent 3-phase network reconnaissance engine with cascading port targeting**

[![Nmap](https://img.shields.io/badge/Nmap-7.94+-blue)](https://nmap.org)
[![Bash](https://img.shields.io/badge/Bash-5.0+-green)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## 🎯 Overview

Automated Nmap scanning framework that intelligently cascades through three phases, using discovered ports from each phase to optimize subsequent scans.

```
Phase 1: Port Discovery    → Fast SYN scan (all 65535 ports)
Phase 2: Service Enum      → Version detection on discovered ports only
Phase 3: Deep Analysis     → Vulnerability scanning & OS detection
```

## ✨ Features

- 🚀 **Cascading Intelligence**: Each phase uses results from previous phases
- 🎨 **Colored Output**: Beautiful terminal interface with real-time progress
- 📊 **Multiple Formats**: Outputs in .txt, .xml, and .gnmap formats
- ⚡ **Configurable Timing**: Support for T0-T5 timing templates
- 📁 **Organized Results**: Timestamped directories with phase separation
- 🔍 **Double Verbosity**: Enhanced scanning details (-vv flag)

## 📦 Installation

```bash
git clone https://github.com/yourusername/nmap-cascade.git
cd nmap-cascade
chmod +x nmap-cascade.sh
```

## 🚀 Usage

```bash
sudo ./nmap-cascade.sh
```

**Interactive prompts will request:**

- Scan name (mandatory)
- Timing template: T0-T5 (mandatory)
- Target IP or hostname

## 📋 Example

```bash
$ sudo ./nmap-cascade.sh

Scan Name: production-scan
Timing: T4
Target: 192.168.1.100

[✓] Phase 1: Discovered 23 open ports
[✓] Phase 2: Service enumeration complete
[✓] Phase 3: Deep analysis finished

Results saved in: nmap_production-scan_20260106_143022/
```

## 📂 Output Structure

```
nmap_<scan-name>_<timestamp>/
├── <scan-name>_phase-1.txt|xml|gnmap    # Port discovery
├── <scan-name>_phase-2.txt|xml|gnmap    # Service enumeration
├── <scan-name>_phase-3.txt|xml|gnmap    # Deep analysis
└── SUMMARY.txt                           # Quick overview
```

## ⚙️ Requirements

- Nmap 7.0+
- Bash 4.0+
- Root/sudo privileges (recommended)

---

⭐ If you find this useful, please star the repo!
