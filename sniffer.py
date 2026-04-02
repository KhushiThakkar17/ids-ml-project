from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import os

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
LOG_FILE = "packet_log.csv"
PACKET_COUNT = 50  # how many packets to capture

# ──────────────────────────────────────────
# SETUP: Create log file with headers
# ──────────────────────────────────────────
def setup_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "size"])
        print(f"[+] Log file created: {LOG_FILE}")

# ──────────────────────────────────────────
# CORE: Process each captured packet
# ──────────────────────────────────────────
def process_packet(packet):

    # Only process packets that have an IP layer
    if not packet.haslayer(IP):
        return

    # Extract basic info
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip    = packet[IP].src
    dst_ip    = packet[IP].dst
    size      = len(packet)

    # Figure out protocol and ports
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        src_port = "-"
        dst_port = "-"

    else:
        protocol = "OTHER"
        src_port = "-"
        dst_port = "-"

    # Print to terminal
    print(f"[{timestamp}] {protocol} | {src_ip}:{src_port} → {dst_ip}:{dst_port} | {size} bytes")

    # Save to log file
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size])

# ──────────────────────────────────────────
# MAIN: Start sniffing
# ──────────────────────────────────────────
def main():
    setup_log()
    print(f"\n[*] Starting packet capture... ({PACKET_COUNT} packets)\n")
    sniff(count=PACKET_COUNT, prn=process_packet, store=False)
    print(f"\n[+] Done! Packets saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
