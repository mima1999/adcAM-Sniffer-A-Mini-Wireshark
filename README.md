🔍 adcAM Sniffer v5.1

<div align="center">

<!-- Top animated GIF separator -->

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

<!-- Animated main title using high-contrast colors -->

<img src="https://www.google.com/search?q=https://readme-typing-svg.herokuapp.com%3Ffont%3DOrbitron%26weight%3D700%26size%3D30%26duration%3D2000%26pause%3D500%26color%3DFFD60A%26center%3Dtrue%26vCenter%3Dtrue%26width%3D550%26lines%3DAdvanced%252BPacket%252BAnalysis%253BReal-Time%252BCredential%252BSniffer%253BSecurity%252BTesting%252BTool" alt="Animated Title" />

Developed by Amin Moniry (adc7)

<!-- Dynamic Status Badges with Custom High-Contrast Style -->

<!-- Animated GIF separator -->

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

🔗 Quick Navigation

<!-- Fixed internal anchor links for navigation -->

🌟 Overview • ✨ Features • 🚀 Installation • 🎮 Usage • 📸 Screenshots • 🛡️ Security • 📞 Contact

</div>

🌟 Overview

adcAM Sniffer is a powerful, real-time network packet analyzer designed for security professionals, penetration testers, and network administrators. Built with Python and featuring a modern web-based interface, it provides deep insights into network traffic with advanced credential detection capabilities.

🎯 Key Highlights

🔴 Real-Time Credential Detection with instant red alert system

🌐 Multi-Protocol Support (HTTP, HTTPS, DNS, FTP, TCP, UDP, ARP)

📊 Live Traffic Dashboard with beautiful visualizations

🔐 Enhanced Security with bcrypt authentication

💾 PCAP Export for Wireshark compatibility

🎨 Modern UI with Nord color scheme

⚡ High Performance with multi-threading support

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

<div align="center">

📈 Project Metrics <img src="https://www.google.com/search?q=https://media.giphy.com/media/HVX4K3zL9j5gVqD7jW/giphy.gif" width="30">

<!-- GitHub Stats card (live updating) with high-contrast theme -->

<img width="49%" src="https://www.google.com/search?q=https://github-readme-stats.vercel.app/api%3Fusername%3DAmin-moniry-pr7%26show_icons%3Dtrue%26theme%3Dreact%26hide_border%3Dtrue%26bg_color%3D10002B%26title_color%3DE0AAFF%26icon_color%3DFFD60A%26text_color%3DFFFFFF%26count_private%3Dtrue%26custom_title%3D📊+Repository+Stats" alt="GitHub Stats" />

<!-- Top Languages card (live updating) with high-contrast theme -->

<img width="49%" src="https://www.google.com/search?q=https://github-readme-stats.vercel.app/api/top-langs/%3Fusername%3DAmin-moniry-pr7%26layout%3Dcompact%26theme%3Dreact%26hide_border%3Dtrue%26bg_color%3D10002B%26title_color%3DE0AAFF%26text_color%3DFFFFFF%26custom_title%3D💻+Most+Used+Languages" alt="Top Languages" />

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

✨ Features

🕵️ Advanced Packet Analysis

Deep Packet Inspection: Analyze all network layers (IP, TCP, UDP, Application)

Protocol Recognition: Automatic detection of HTTP, HTTPS, DNS, FTP, and more

Domain Resolution: Smart DNS cache and reverse lookup

Port Scanning Detection: Track source and destination ports

🚨 Credential Detection System

Multi-Pattern Recognition: Detects usernames, passwords, emails, tokens, and API keys

Real-Time Alerts: Visual and sound notifications when credentials are found

Smart Filtering: Eliminates false positives with intelligent validation

Export Capabilities: Save detected credentials to TXT format

📈 Live Monitoring Dashboard

Real-Time Packet Stream: See packets as they arrive

Protocol Statistics: Top protocols and ports visualization

Session Summary: Comprehensive traffic analysis

Display Filters: Live filtering by IP, protocol, or domain

🔒 Security Features

User Authentication: Secure login with bcrypt password hashing

Machine ID Binding: Prevents unauthorized account sharing

Rate Limiting: Protection against brute-force attacks

Database Encryption: Secure storage of user credentials

💾 Export & Save

PCAP Files: Export individual or all packets for Wireshark

Credential Reports: TXT export of all detected sensitive data

Session Management: Name and organize capture sessions

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

🚀 Installation

Prerequisites

# Python 3.8 or higher
python --version

# Windows: Npcap (Required for packet capture)
# Download from: [https://nmap.org/npcap/](https://nmap.org/npcap/)


Step 1: Clone Repository

git clone [https://github.com/Amin-moniry-pr7/adcAM-Sniffer.git](https://github.com/Amin-moniry-pr7/adcAM-Sniffer.git)
cd adcAM-Sniffer


Step 2: Install Dependencies

pip install -r requirements.txt


Step 3: Install Npcap (Windows)

Download Npcap from https://nmap.org/npcap/

Install with WinPcap API-compatible Mode enabled

Restart your computer

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

🎮 Usage

Starting the Application

Windows (Administrator Required)

# Right-click Command Prompt → Run as Administrator
python run.py


Linux/Mac (Root Required)

sudo python3 run.py


First-Time Setup

Register an Account
   - Click "Register" on the welcome screen
   - Enter username and password
   - Input your activation code
   - Click "Register"

Login
   - Enter your credentials
   - Click "Login"
   - Wait for the splash screen animation

Select Network Interface
   - Choose your active network adapter from the dropdown
   - Green dot indicates interface is up and running

Basic Workflow

1. Set Capture Filter (Optional)

   - Select a quick filter (HTTP, HTTPS, DNS, FTP, ICMP)
   - Or leave blank to capture all traffic

2. Start Sniffing

   - Click the green "▶ Start Sniffing" button
   - Monitor live packets in the table
   - Watch for red-highlighted rows (credentials detected!)

3. Apply Display Filters

   - Type in the "Display Filter" box to filter visible packets
   - Example: 192.168.1.1, http, google.com

4. View Packet Details

   - Click any packet row to open detail modal
   - Tabs: Summary | Layer Details | Raw Payload
   - Save individual packets as PCAP

5. Check Credentials Tab

   - Red badge shows number of credentials found
   - View all detected sensitive data
   - Export credentials to TXT file

6. Export Data

   - Save All (PCAP): Export entire capture session
   - Export Credentials (TXT): Save credential report
   - Individual Packets: Save specific packets

7. Stop & Clear

   - Click "■ Stop Sniffing" to end capture
   - Use "🗑️ Clear All" to reset session

🎨 Interface Guide

Main Dashboard Sections

<!-- IMPORTANT: Replace this text with an Animated GIF or high-quality PNG of the real-time Nord Theme UI. -->

Protocol Color Coding

🔴 HTTP: Red (Unencrypted traffic)

🟢 HTTPS: Green (Encrypted traffic)

🟠 FTP: Orange (File transfer)

🟣 DNS: Purple (Domain lookups)

🔵 TCP: Blue (General TCP)

🟡 UDP: Yellow (General UDP)

📸 Screenshots

<!-- IMPORTANT: Replace these placeholders with actual screenshots or animated GIFs of your application. -->

Welcome Screen

Live Packet Capture

[Animated GIF or Screenshot of the real-time packet table with data flowing and color coding]

Credential Alert

[Screenshot of the red alert notification modal showing detected credentials]

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

🔧 Advanced Features

BPF (Berkeley Packet Filter) Examples

# Capture only HTTP traffic
"tcp port 80"

# Capture HTTP and HTTPS
"tcp port 80 or tcp port 443"

# Capture traffic from specific IP
"host 192.168.1.100"

# Capture DNS queries
"udp port 53"

# Capture FTP
"tcp port 21 or tcp port 20"

# Exclude certain IPs
"not host 192.168.1.1"

# Capture only TCP SYN packets
"tcp[tcpflags] & tcp-syn != 0"


Display Filter Examples

# Filter by IP address
192.168.1.100

# Filter by protocol
http

# Filter by domain
facebook.com

# Filter by port (in Info column)
:443


<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

🛡️ Security Considerations

⚠️ Important Warnings

Legal Use Only: Only use on networks you own or have explicit permission to test

Administrator Rights: Requires elevated privileges to capture packets

Sensitive Data: All captured credentials are stored locally

Network Impact: May cause increased network load during capture

🔐 Security Features

bcrypt Password Hashing: Industry-standard password protection

Machine ID Binding: Prevents unauthorized account sharing

Rate Limiting: Protection against brute-force attacks

Session Management: Automatic timeout and secure session handling

Input Validation: SQL injection and XSS protection

📋 Best Practices

✅ Always use on isolated test networks

✅ Clear sensitive data after testing

✅ Use strong passwords for registration

✅ Keep activation codes confidential

✅ Run antivirus scans regularly

✅ Update to latest version

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

🐛 Troubleshooting

Common Issues

Issue: "No interfaces found"

Solution: 

Run as Administrator (Windows) or sudo (Linux)

Install Npcap/WinPcap

Check if network adapters are enabled

Issue: "Failed to start sniffing"

Solution:

Verify administrator privileges

Check firewall settings

Ensure Npcap is installed correctly

Try different network interface

Issue: "Import Error"

Solution:

pip install --upgrade -r requirements.txt


Issue: Database locked

Solution:

Close all instances of the application

Delete app_data.db and restart

Re-register your account

Issue: Browser not opening

Solution:

Check if port 8080 is available

Manually open: http://localhost:8080

Install Chrome/Chromium browser

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

📊 Technical Specifications

System Requirements

Component

Minimum

Recommended

OS

Windows 10, Linux, macOS

Windows 11, Ubuntu 22.04

Python

3.8+

3.11+

RAM

2 GB

4 GB+

Disk Space

100 MB

500 MB

Network

Any NIC

Gigabit Ethernet

Dependencies

eel>=0.14.0          # GUI framework
scapy>=2.4.5         # Packet manipulation
psutil>=5.8.0        # System utilities
bcrypt>=3.2.0        # Password hashing
gevent>=21.0.0       # Async networking
bottle>=0.12.19      # Web server


Architecture

adcAM-Sniffer/
│
├── app/
│   ├── __init__.py
│   └── application.py        # Core backend logic
│
├── web/
│   ├── index.html            # Main UI
│   ├── style.css             # Nord theme styling
│   ├── script.js             # Frontend logic
│   └── logo.ico              # Application icon
│
├── run.py                    # Entry point
├── requirements.txt          # Dependencies
├── LICENSE                   # Non-commercial license
├── .gitignore               # Git ignore rules
└── README.md                # This file


🎓 Educational Purpose

This tool is designed for:

📚 Network Security Education: Learn packet analysis

🔬 Penetration Testing: Authorized security assessments

🧪 Research: Academic network protocol studies

🛠️ Development: Testing network applications

Learning Resources

Wireshark Documentation

Scapy Tutorial

BPF Filter Guide

Network Protocol Basics

🤝 Contributing

Contributions are welcome! Please follow these guidelines:

Fork the repository

Create a feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

Development Setup

# Clone your fork
git clone [https://github.com/YOUR_USERNAME/adcAM-Sniffer.git](https://github.com/YOUR_USERNAME/adcAM-Sniffer.git)

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dev dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest


📄 License

Non-Commercial Use License v3.0

Copyright © 2025 Amin Moniry (adc7). All rights reserved.

✅ Permitted Uses

Personal, educational, and research purposes

Non-profit organization activities

Legitimate security testing and penetration testing

Modification for non-commercial purposes

❌ Prohibited Uses

Any commercial use or financial gain

Selling, licensing, or commercializing the software

Providing paid services using this software

Integration into commercial products

For commercial licensing inquiries:

📧 Email: aminmoniry199@gmail.com

🌐 GitHub: Amin-moniry-pr7

📞 Contact & Support

Get Help

🐛 Bug Reports: Open an Issue

💡 Feature Requests: Submit Request

📖 Documentation: Check this README

Connect

Developer: Amin Moniry (adc7)

Email: aminmoniry199@gmail.com

GitHub: github.com/Amin-moniry-pr7

🏆 Acknowledgments

Special thanks to:

Scapy Team - Powerful packet manipulation library

Eel Project - Seamless Python-JavaScript integration

Nord Theme - Beautiful color scheme

Open Source Community - Inspiration and support

📈 Version History

v5.1 (Current) - 2025

✨ Enhanced credential detection with multi-pattern recognition

🚀 Improved performance with infinite scroll pagination

🎨 Modern UI with Nord color scheme

🔐 Enhanced security with bcrypt authentication

💾 Database storage for packet persistence

🐛 Bug fixes and stability improvements

v5.0 - 2024

🎉 Complete UI redesign

📊 Real-time statistics dashboard

🔍 Advanced filtering capabilities

v4.x - 2024

Initial public release

Basic packet capture functionality

Credential detection system

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

⚡ Quick Start Cheatsheet

# 1. Install
git clone [https://github.com/Amin-moniry-pr7/adcAM-Sniffer.git](https://github.com/Amin-moniry-pr7/adcAM-Sniffer.git)
cd adcAM-Sniffer
pip install -r requirements.txt

# 2. Run (as Admin/Root)
python run.py

# 3. Register → Login → Select Interface → Start Sniffing

# 4. Monitor credentials in real-time!


<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

🌟 Star History

<!-- Dynamic Star History chart with dark theme -->

<div align="center">

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%">

<div align="center">

Built with ❤️ by Amin Moniry

Making network security accessible to everyone

<!-- Footer Badges with High Contrast Colors -->

⚠️ Use Responsibly | 🔒 Security First | 📚 Education Focused

</div>
