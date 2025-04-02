from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import os
import time
from tabulate import tabulate

def scan_wifi():
    networks = {}
    clients = {}
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr2
            essid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            channel = ord(pkt[Dot11Elt:3].info) if pkt[Dot11Elt:3] else "?"
            pwr = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "?"
            
            crypto = "OPN"
            auth = "OPN"
            if pkt.haslayer(Dot11Elt):
                cap = pkt.sprintf("%Dot11Beacon.cap%")
                if "privacy" in cap:
                    crypto = "WEP"
                if pkt.haslayer(Dot11Elt, ID=48):
                    crypto = "WPA2"
                    auth = "PSK"
                elif pkt.haslayer(Dot11Elt, ID=221):
                    crypto = "WPA"
                    auth = "PSK"
                if pkt.haslayer(Dot11Elt, ID=45):
                    crypto = "WPA3"
                    auth = "MGT"
            
            networks[bssid] = (essid, crypto, auth, channel, pwr)
        
        elif pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype in [0x04, 0x05]:  # Probe Request or Association Request
            sta_mac = pkt[Dot11].addr2
            ap_mac = pkt[Dot11].addr1 if pkt.subtype == 0x05 else "(not associated)"
            clients[sta_mac] = ap_mac
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Capturing nearby Wi-Fi networks...")
    
    sniff(iface="WiFi 2", prn=packet_handler, timeout=10, store=0)
    
    print(tabulate([(essid, bssid, enc, auth, ch, pwr) for bssid, (essid, enc, auth, ch, pwr) in networks.items()],
                   headers=["ESSID", "BSSID", "Encryption", "Auth", "CH", "PWR"], tablefmt="grid"))
    
    for client, ap in clients.items():
        print(f"Client MAC: {client} -> {ap}")
    
if __name__ == "__main__":
    while True:
        scan_wifi()
        time.sleep(5)
