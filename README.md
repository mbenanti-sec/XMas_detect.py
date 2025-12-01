# XMas_detect.py
Passive XMas scan detector that listens on a network interface and alerts when TCP packets have FIN, PSH and URG flags set (typical XMas scan).

XMas_detect is a simple IDS-style script that detects TCP "XMas" scan
packets. It uses scapy to sniff TCP traffic on a given interface and checks
whether the FIN, PSH and URG flags are all set, which is characteristic of
XMas scans.

Features

Sniffs TCP packets in real time on a specified interface

Detects XMas packets using a bit mask:

FIN = 0x01

PSH = 0x08

URG = 0x20

Combined mask = 0x29

Logs:

Source IP

Destination IP

Destination port

TCP flags

Requirements

Python 3

scapy

Root/administrator privileges

Install:

pip install scapy


Usage

Edit the interface in the script if necessary:

IFACE = "eth0"  # change to your interface (eth0, enp0s3, wlan0, ...)


Then run:

sudo python3 XMas_detect.py

Example output:

[+] listen on eth0 for packet XMas (FIN+PSH+URG)...
[XMAS] detected XMas packet: 10.0.0.5 -> 10.0.0.10:80 flags=41


Disclaimer

This script is intended for network security training and to understand
how reconnaissance scans like XMas scans can be detected.
Only monitor traffic on networks you are authorized to analyze.
