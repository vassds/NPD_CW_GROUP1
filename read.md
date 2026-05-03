# Python Network Discovery & Auditing Tool

## Project Overview
This project is a high-performance, multi-threaded TCP network scanner written in Python. Developed as an internal auditing tool, it identifies active hosts and open TCP ports across specific subnets. The tool transitions away from slow, synchronous scans by leveraging Python's `concurrent.futures` to manage a highly configurable thread pool, ensuring enterprise-grade speed and reliability.

## Key Features
* **Multi-threaded Architecture:** Uses ThreadPoolExecutor for lightning-fast port scanning.
* **Subnet Support:** Parses standard single IP addresses and full CIDR blocks (e.g., `192.168.1.0/24`) using Python's `ipaddress` module.
* **Smart Timeouts:** Gracefully handles filtered ports and dropped packets without hanging.
* **Robust CLI Interface:** Uses `argparse` for a professional user experience.
* **Service Banner Grabbing:** Attempts to pull service banners to identify running applications on open ports.
* **JSON Reporting:** Allows users to export scan results into a structured JSON file for further auditing.

## Prerequisites
* Python 3.6 or higher.
* No external dependencies are required (built entirely using Python Standard Libraries).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/vassds/NPD_CW_GROUP1.git
