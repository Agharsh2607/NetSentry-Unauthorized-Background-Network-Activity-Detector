import scapy.all as scapy
import psutil
import socket
from datetime import datetime

# Simple whitelist to avoid alert fatigue
WHITELIST_PROCS = ["chrome.exe", "msedge.exe", "svchost.exe", "spotify.exe"]
WHITELIST_IPS = ["127.0.0.1", "0.0.0.0"]

def get_process_from_port(local_port):
    """Maps a local port to a process name."""
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == local_port:
            try:
                process = psutil.Process(conn.pid)
                return process.name(), conn.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return "Unknown", None
    return "Unknown", None

def monitor_packet(packet):
    """Callback function for every captured packet."""
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        dest_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport
        
        # Filter for outbound traffic only
        if dest_ip not in WHITELIST_IPS:
            proc_name, pid = get_process_from_port(src_port)
            
            if proc_name not in WHITELIST_PROCS:
                print(f"--- [SUSPICIOUS ACTIVITY] ---")
                print(f"Time: {datetime.now()}")
                print(f"Process: {proc_name} (PID: {pid})")
                print(f"Destination: {dest_ip}")
                print(f"Port: {src_port}")
                print("-" * 30)

print("Starting Network Monitor...")
# Sniffing on the default interface (requires Admin/Sudo)
scapy.sniff(prn=monitor_packet, store=0)