# Intrusion-Detection-System---Python



# Handmade IDS

A custom Python-based Intrusion Detection System (IDS) inspired by SNORT-like rule logic.

This project was built as a Proof of Concept (POC) to demonstrate packet inspection, rule parsing, traffic analysis, and basic network threat detection using Python and Scapy.

The system can monitor:
- Live network traffic (sniffing)
- PCAP files (offline analysis)

and detect suspicious activity based on custom SNORT-style rules.

---

# Features

## Current Detection Capabilities

The current version supports detection of:

- TCP SYN Scan Detection
- HTTP Path Traversal Detection
- ICMP Echo Request Detection

The detection engine works using pre-made SNORT-like rules that are parsed into JSON and analyzed dynamically against network traffic.

---

# Technologies Used

- Python 3
- Scapy
- JSON
- Packet Sniffing
- PCAP Analysis
- Rule-Based Detection Logic

---

# Project Structure


main.py
local_rules.txt
local_rules.json

main.py → Main IDS engine
local_rules.txt → Custom SNORT-like rules
local_rules.json → Parsed rules database generated automatically
Example Rule Format
alert tcp any any -> any 80 (msg:"Possible SYN Scan detected"; flags:S; sid:10001; rev:1;)

The parser converts the rules into JSON and the detection engine evaluates packets against them.

How It Works
1. Rule Parsing

The engine reads SNORT-like rules from a text file and converts them into structured JSON.

2. Rule Validation

Rules are validated by:

Protocol support
Required fields
SID existence
Basic syntax validation
3. Detection Engine

Each packet is checked against:

IP matching
Port matching
TCP flags
Payload content
Protocol-specific logic
4. Alert Generation

If a packet matches a rule:

An alert is created
The alert is displayed or written to a file
Running the IDS:

Live Sniffing Mode
python main.py

Choose:

s for sniffing
Your network interface name

Example:

Intel(R) 82579V Gigabit Network Connection
PCAP Analysis Mode

Choose:

p for PCAP mode

Then provide:

PCAP file path

The IDS will analyze all packets inside the capture.

Example Alert
[ALERT] {
    'sid': 10001,
    'msg': 'Possible SYN Scan detected',
    'src_ip': '10.0.0.51',
    'dst_ip': '1.1.1.1',
    'timestamp': datetime.datetime(...)
}
Important Notes

This project is currently a POC (Proof of Concept).

The current rule database is intentionally small because the focus was building:

The detection engine
Rule parsing logic
Packet inspection architecture
Offline + live traffic analysis support

The rule set and detection capabilities will grow significantly in future versions.

Future Improvements

Planned future features include:

Detection Enhancements
More SNORT-compatible rules
Stateful detection
Threshold-based alerts
Port scan correlation
Brute-force detection
DNS tunneling detection
Beaconing detection
Automation
Automatic local rule updates
Rule downloading system
Dynamic rule loading
Performance
Multi-threaded packet processing
Faster packet filtering
Optimized detection pipeline
User Experience
Web dashboard
Visual alert system
Real-time monitoring interface
Alert statistics
Logging system
Advanced Features
Email alerts
SIEM integration
Threat intelligence feeds
Machine learning anomaly detection
REST API
Why This Project Exists

This project was created as a hands-on cybersecurity learning project focused on:

Network traffic analysis
Detection engineering
IDS architecture
Packet parsing
Cyber threat detection concepts

The goal was to build an IDS completely from scratch to deeply understand how real detection systems operate internally.

Author

Created by:

Shachar Levi Friedman
Disclaimer

This project is intended for:

Educational purposes
Cybersecurity learning
Research environments
Authorized testing only

Do not use this project on networks you do not own or have permission to monitor.
