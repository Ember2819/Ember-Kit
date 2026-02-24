# Emberkit Cybersecurity Utility
## https://ember2819.github.io/Ember-Kit/
A Python-based cybersecurity utility featuring several network tools, with more features on the way.
This program is for educational purposes only. DO NOT do anything illegal. I'm not responsible for anything you do with this script.

---

## Installation

### Prerequisites: Python 3 & Pip 3

Download and install Python from the [official Python.org downloads page](https://www.python.org/downloads/).

- **Windows:** Select the "Windows installer" for your desired version.
- **macOS:** Select the appropriate `.pkg` file.
- **Linux:** Use your package manager, e.g.:
  ```bash
  sudo apt install python3-pip
  ```

---

## Getting Started

### macOS / Linux

1. Download and unzip the code.
2. Open a terminal and navigate to the project folder:
   ```bash
   cd /path/to/folder
   ```
3. Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```
4. Run the program:
   ```bash
   sudo python3 main.py
   ```
5. Enter your password when prompted and enjoy the program!

### Windows

> Windows support has not been fully tested. The steps should be similar to macOS/Linux — install Python 3, install dependencies via `pip`, and run `main.py`. Contributions welcome!

---

## Features

### 1. LAN Scanner
Automatically detects your local area network and prints the **IP address** and **MAC address** of all devices found on it.

### 2. IP Geolocation
Takes an IP address as input and returns the associated **ISP**, **general location**, and **country**.

### 3. Keyword File Searcher
Similar to `grep`. Accepts a file path and searches it for specified keywords.

### 4. Ping
Pings a given IP address to determine whether it is currently **online or offline**.

### 5. Hash Tools
Uses a dictionary attack from a custom wordlist to crack multiple different types of password hashes.

### 6. Man in the Middle Attack
This is an advanced tool that uses ARP spoofing to execute a Man in the Middle Attack. You will need the victims IP and the routers IP. This script is for educational purposes only don't do anything illegal.
