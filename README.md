# PacketSniffer: Cross-Platform Network Analyzer

**PacketSniffer** is a powerful, real-time network packet analyzer built in Python. It captures, decodes, and displays live packet data on **Windows** and **Linux**, supporting detailed inspection of **Ethernet**, **IPv4/IPv6**, **TCP**, **UDP**, and **ICMP/ICMPv6** traffic. 

## ✨ New: Modern GUI Application (Windows)
We have added a **Modern Dark Mode GUI** and a standalone **Executable** for easier use!

### 📦 Download & Run (No Python Required)
1. Go to the `dist` folder.
2. Run **`NetworkSniffer.exe`**.
3. Accept the **UAC Prompt** (Administrator rights are required for packet sniffing).
4. Click **Start Capture** to begin. 

---

## 🚀 Features

* **Modern GUI Interface** (Windows):
  * Live packet table with auto-scrolling.
  * Protocol filtering (TCP, UDP, IPv6, ICMP).
  * Detailed packet inspection (Hex + ASCII payload).
  * Save captures to JSON.
* **CLI Mode** (Legacy):
  * Runs in terminal for quick analysis or Linux servers.
* **Protocol Decoding**:
  * Ethernet, IPv4, IPv6
  * TCP (Flags, Sequence/Ack), UDP, ICMP
* **Smart Details**:
  * Source/Destination IPs and Ports
  * Protocol Names and Service mapping
* **Cross-Platform**:
  * GUI & Exe: Windows Only
  * CLI Script: Windows & Linux

---

## 🛠 Installation (Source Code)

If you want to run from source instead of the `.exe`:

### Requirements
* Python 3.8+
* Admin/root privileges

### Dependencies
Install the required libraries:
```bash
pip install customtkinter pyinstaller
```

### Running the App
**GUI Mode:**
```bash
python SnifferApp.py
```

**CLI Mode:**
```bash
python Sniffer.py
```
*(Note: Must run terminal as Administrator/Sudo)*

---

## 📦 Output Formats

* **JSON Export**: Complete structured data including timestamps, headers, and payloads.
* **Live View**: Real-time updates in the application window or terminal console.

---

## ⚠️ Permissions
* **Windows**: Must run as Administrator.
* **Linux**: Must run with `sudo`.
* Without proper permissions, raw sockets cannot capture traffic.

---


## 🧠 Technical Overview

* **Raw Sockets** used to read low-level packets.
* Protocol headers are parsed using `struct.unpack`.
* Packet saving is handled via JSON serialization.
* Filtering uses protocol number mapping (e.g., TCP = 6).
* IP and MAC addresses are formatted for readability.

---


