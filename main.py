import requests
import os
import hash_tools
import json
import time
import ipaddress
import netifaces
from scapy.all import ARP, Ether, srp
from colorama import Fore, Style, init
from ping3 import ping

init(autoreset=True)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

logo = f"""{Fore.CYAN}
 ██████████                 █████                        █████   ████  ███   █████   
░░███░░░░░█                ░░███                        ░░███   ███░  ░░░   ░░███    
 ░███  █ ░  █████████████   ░███████   ██████  ████████  ░███  ███    ████  ███████  
 ░██████   ░░███░░███░░███  ░███░░███ ███░░███░░███░░███ ░███████    ░░███ ░░░███░   
 ░███░░█    ░███ ░███ ░███  ░███ ░███░███████  ░███ ░░░  ░███░░███    ░███   ░███    
 ░███ ░   █ ░███ ░███ ░███  ░███ ░███░███░░░   ░███      ░███ ░░███   ░███   ░███ ███
 ██████████ █████░███ █████ ████████ ░░██████  █████     █████ ░░████ █████  ░░█████ 
░░░░░░░░░░ ░░░░░ ░░░ ░░░░░ ░░░░░░░░   ░░░░░░  ░░░░░     ░░░░░   ░░░░ ░░░░░    ░░░░░                                                                                 
{Style.RESET_ALL}
"""

def auto_detect_network():
    gws = netifaces.gateways()
    default = gws.get('default')

    if netifaces.AF_INET in default:
        interface = default[netifaces.AF_INET][1]
        addr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip = addr['addr']
        netmask = addr['netmask']
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    else:
        return None

def scan(network):
    print(Fore.YELLOW + f"\nScanning {network}...\n")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


def print_devices(devices):
    print(Fore.GREEN + "\n--- Devices Found ---\n")

    for device in devices:
        print(
            Fore.CYAN + device["ip"] +
            Fore.WHITE + "  |  " +
            Fore.MAGENTA + device["mac"]
        )

def ip_geolocation():
    ip = input(Fore.YELLOW + "Enter IP address: ")

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        if data["status"] == "success":
            print(Fore.GREEN + "\n--- Location Info ---")
            print(Fore.CYAN + "Country: " + Fore.WHITE + data["country"])
            print(Fore.CYAN + "Region:  " + Fore.WHITE + data["regionName"])
            print(Fore.CYAN + "City:    " + Fore.WHITE + data["city"])
            print(Fore.CYAN + "ISP:     " + Fore.WHITE + data["isp"])
        else:
            print(Fore.RED + "Invalid IP address.")

    except Exception as e:
        print(Fore.RED + "Error:", e)

def find_keywords_case_sensitive(file_path, keyword):
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_number, line in enumerate(f, start=1):
            if keyword in line:
                print(f"{line_number}: {line.strip()}")

def find_keywords_case_insensitive(file_path, keyword):
    keyword_lower = keyword.lower()
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_number, line in enumerate(f, start=1):
            if keyword_lower in line.lower():
                print(f"{line_number}: {line.strip()}") 

def ping_host():
    host = input(Fore.YELLOW + "Enter host to ping: ")
    response = ping(host)
    if response is not None:
        print(Fore.GREEN + f"Ping successful: {response} ms")
    else:
        print(Fore.RED + "Ping failed.")

def main():
    while True:
        clear()
        print(logo)

        print(Fore.BLUE + "--- Options ---")
        print(Fore.CYAN + "1: Scan LAN")
        print(Fore.CYAN + "2: IP Geolocation")
        print(Fore.CYAN + "3: Find Keywords")
        print(Fore.CYAN + "4: Ping a Host")
        print(Fore.CYAN + "5: Hash Tools")
        print(Fore.CYAN + "6: Exit")

        choice = input(Fore.YELLOW + "\nSelect an option: ")

        if choice == "1":
            network = auto_detect_network()

            if network:
                print(Fore.GREEN + f"\nAuto-detected network: {network}")
            else:
                print(Fore.RED + "Could not auto-detect network.")
                network = input("Enter network manually: ")

            devices = scan(network)

            if not devices:
                print(Fore.RED + "No devices found.")
            else:
                print_devices(devices)

            input(Fore.YELLOW + "\nPress Enter to return to menu...")

        elif choice == "2":
            ip_geolocation()
            input(Fore.YELLOW + "\nPress Enter to return to menu...")

        elif choice == "3":
            file_path = input(Fore.YELLOW + "Enter file path: ")
            keyword = input(Fore.YELLOW + "Enter keyword: ")

            print(Fore.BLUE + "\n--- Case Sensitive ---")
            find_keywords_case_sensitive(file_path, keyword)

            print(Fore.BLUE + "\n--- Case Insensitive ---")
            find_keywords_case_insensitive(file_path, keyword)

            input(Fore.YELLOW + "\nPress Enter to return to menu...")

        elif choice == "4":
            ping_host()
            input(Fore.YELLOW + "\nPress Enter to return to menu...")

        elif choice == "5":
            hash_tools.run_hash_cracker()
            input(Fore.YELLOW + "\nPress Enter to return to menu...")

        elif choice == "6":
            print(Fore.GREEN + "Goodbye.")
            break

        else:
            print(Fore.RED + "Invalid Option.")
            time.sleep(1)

main()
