# 🌌 BAVO // NETWORK PROXY
> **Neural Link for Secure Traffic Management**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![UI](https://img.shields.io/badge/UI-Custom_Tkinter-cyan?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

### 🌐 Overview
**Bavo Proxy** is a high-performance, multi-threaded networking core designed for traffic inspection and administrative control. Wrapped in a sharp, **High-DPI Cyberpunk-inspired interface**.


---

### ⚡ Core Systems

*   🚀 **Dual-Protocol Engine:** A unified core that handles both **SOCKS5 (TCP/UDP)** and **HTTP** traffic on a single port.
*   📊 **Neural Stream Visualization:** Real-time **Oscilloscope monitors** for Inbound (DL) and Outbound (UL) traffic with dynamic scaling.
*   🔍 **Advanced Fingerprinting:** Built-in OS detection identifies connected nodes as Windows, Android, iOS, Mac, or Linux systems.
*   💾 **Persistent Node Tracking:** Connected users remain in the registry even after disconnection for session auditing and historical tracking.
*   🕶️ **Stealth Integration:** Full **System Tray** support with custom iconography for background operation.

---

### 🛡️ Firewall & Administrative Control

*   🚫 **Instant IP Neutralization:** One-click banning that flushes all active sockets and blacklists the source IP.
*   🚧 **Domain Interception:** Enforce global domain blacklists or assign specific restricted lists to individual users.
*   📉 **Bandwidth Shaping:** Define per-user speed limits (KB/s) to ensure fair resource allocation.
*   🚨 **Panic Protocols:** Execute a mass-block on all currently active, non-whitelisted nodes with a single command.
*   🔗 **Neural Link Monitoring:** A live view of every active socket, including target host, source node, and link duration.

---

### 🖥️ Neural Interface (UI) Features

*   💎 **Crisp Resolution:** High-DPI awareness logic ensures the interface is pixel-perfect on 4K and modern displays.
*   🖼️ **Custom Frame Logic:** Borderless window design with professional Windows integration (Taskbar support & Snapping).
*   📜 **Scrollable Configuration:** A dynamic, scroll-ready settings panel ensuring the **"Flash Memory (Save)"** button is always reachable.
*   🎨 **Themed Aesthetics:** A curated color palette utilizing *bg_void*, *neon_cyan*, and *neon_purple*.

---

### 🛠️ Initialization & Setup

#### 1. Prerequisites
To initialize the Bavo Core, **Python 3.8+** is required.

#### 2. Dependencies
```bash
pip install pillow pystray
```
Note: If these libraries are missing, the proxy core will still function, but tray features will be disabled.
```bash
3. Quick Start

# Clone the Repository
git clone https://github.com/bawanu/bavo-proxy.git

# Enter Directory
cd bavo-proxy
# Launch the Core
python bavo_proxy.py
```
⚙️ Core Parameters
Parameter	Description
Bind IP	The local network interface to listen on (Default: 0.0.0.0).
Global Speed Limit	Throttles total throughput to a specific KB/s.
Max Connections	Prevents socket exhaustion by limiting per-IP links.
Basic Auth	Optional credentials (Username/Password) for proxy access.
🤝 Credits & Support

Developed by Bawan
🔗 Visit GitHub Profile

Disclaimer: Bavo Proxy is intended for administrative network management and educational purposes. Use responsibly and in accordance with local data privacy laws.
