from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
from datetime import datetime
from collections import defaultdict
import csv
import os

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
LOG_FILE     = "packet_log.csv"
ALERT_FILE   = "alerts.csv"
PACKET_COUNT = 200

# Detection thresholds
PORT_SCAN_THRESHOLD   = 10    # unique ports from same IP
SYN_FLOOD_THRESHOLD   = 100   # SYN packets from same IP
ICMP_FLOOD_THRESHOLD  = 50    # ICMP packets from same IP
SSH_BRUTE_THRESHOLD   = 5     # connection attempts to port 22
HTTP_BRUTE_THRESHOLD  = 20    # requests to port 80/443
DNS_TUNNEL_THRESHOLD  = 50    # length of DNS query name

# ──────────────────────────────────────────
# TRACKING DICTIONARIES
# ──────────────────────────────────────────
port_tracker  = defaultdict(set)   # ip → set of ports touched
syn_tracker   = defaultdict(int)   # ip → SYN count
icmp_tracker  = defaultdict(int)   # ip → ICMP count
ssh_tracker   = defaultdict(int)   # ip → SSH attempt count
http_tracker  = defaultdict(int)   # ip → HTTP request count
arp_table     = defaultdict(set)   # ip → set of MACs seen claiming that IP

# ──────────────────────────────────────────
# SETUP LOG FILES
# ──────────────────────────────────────────
def setup_logs():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip",
                             "protocol", "src_port", "dst_port", "size"])

    if not os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "alert_type", "src_ip", "detail"])

    print(f"[+] Logs ready: {LOG_FILE}, {ALERT_FILE}")

# ──────────────────────────────────────────
# ALERT ENGINE
# ──────────────────────────────────────────
def raise_alert(alert_type, src_ip, detail):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n🚨 ALERT [{alert_type}] | IP: {src_ip} | {detail}\n")
    with open(ALERT_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, alert_type, src_ip, detail])

# ──────────────────────────────────────────
# DETECTION #1 — PORT SCAN
# Attacker probes many ports quickly
# ──────────────────────────────────────────
def detect_port_scan(src_ip, packet):
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        port_tracker[src_ip].add(dst_port)

        if len(port_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            raise_alert(
                "PORT SCAN",
                src_ip,
                f"Touched {len(port_tracker[src_ip])} unique ports"
            )
            port_tracker[src_ip].clear()

# ──────────────────────────────────────────
# DETECTION #2 — SYN FLOOD
# Floods server with TCP connection requests
# ──────────────────────────────────────────
def detect_syn_flood(src_ip, packet):
    if packet.haslayer(TCP):
        if packet[TCP].flags == 0x02:  # SYN only
            syn_tracker[src_ip] += 1
            if syn_tracker[src_ip] >= SYN_FLOOD_THRESHOLD:
                raise_alert(
                    "SYN FLOOD",
                    src_ip,
                    f"{syn_tracker[src_ip]} SYN packets detected"
                )
                syn_tracker[src_ip] = 0

# ──────────────────────────────────────────
# DETECTION #3 — ICMP FLOOD
# Ping flood to overwhelm a target
# ──────────────────────────────────────────
def detect_icmp_flood(src_ip, packet):
    if packet.haslayer(ICMP):
        icmp_tracker[src_ip] += 1
        if icmp_tracker[src_ip] >= ICMP_FLOOD_THRESHOLD:
            raise_alert(
                "ICMP FLOOD",
                src_ip,
                f"{icmp_tracker[src_ip]} ICMP packets detected"
            )
            icmp_tracker[src_ip] = 0

# ──────────────────────────────────────────
# DETECTION #4 — SSH BRUTE FORCE
# Repeated login attempts on port 22
# ──────────────────────────────────────────
def detect_ssh_brute(src_ip, packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport == 22 and packet[TCP].flags == 0x02:
            ssh_tracker[src_ip] += 1
            if ssh_tracker[src_ip] >= SSH_BRUTE_THRESHOLD:
                raise_alert(
                    "SSH BRUTE FORCE",
                    src_ip,
                    f"{ssh_tracker[src_ip]} SSH connection attempts"
                )
                ssh_tracker[src_ip] = 0

# ──────────────────────────────────────────
# DETECTION #5 — HTTP BRUTE FORCE
# Hammering a web server / login page
# ──────────────────────────────────────────
def detect_http_brute(src_ip, packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport in [80, 443, 8080]:
            http_tracker[src_ip] += 1
            if http_tracker[src_ip] >= HTTP_BRUTE_THRESHOLD:
                raise_alert(
                    "HTTP BRUTE FORCE",
                    src_ip,
                    f"{http_tracker[src_ip]} HTTP requests detected"
                )
                http_tracker[src_ip] = 0

# ──────────────────────────────────────────
# DETECTION #6 — ARP SPOOFING
# Attacker sends fake ARP replies
# to poison MAC/IP mapping (MITM attack)
# ──────────────────────────────────────────
def detect_arp_spoof(packet):
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:  # ARP reply (is-at)
            src_ip  = packet[ARP].psrc   # claimed IP
            src_mac = packet[ARP].hwsrc  # MAC making the claim

            arp_table[src_ip].add(src_mac)

            if len(arp_table[src_ip]) > 1:
                raise_alert(
                    "ARP SPOOFING",
                    src_ip,
                    f"Multiple MACs claiming IP {src_ip}: {arp_table[src_ip]}"
                )

# ──────────────────────────────────────────
# DETECTION #7 — DNS TUNNELING
# Attacker encodes stolen data in DNS queries
# to exfiltrate data past firewalls
# ──────────────────────────────────────────
def detect_dns_tunnel(src_ip, packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode(errors="ignore")
        if len(query) > DNS_TUNNEL_THRESHOLD:
            raise_alert(
                "DNS TUNNELING",
                src_ip,
                f"Suspiciously long DNS query ({len(query)} chars): {query[:60]}..."
            )

# ──────────────────────────────────────────
# PACKET PROCESSOR — runs on every packet
# ──────────────────────────────────────────
def process_packet(packet):

    # ── Log IP-based packets ──
    if packet.haslayer(IP):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size   = len(packet)

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

        print(f"[{timestamp}] {protocol} | {src_ip}:{src_port} → {dst_ip}:{dst_port} | {size} bytes")

        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip,
                            protocol, src_port, dst_port, size])

        # Run all IP-based detections
        detect_port_scan(src_ip, packet)
        detect_syn_flood(src_ip, packet)
        detect_icmp_flood(src_ip, packet)
        detect_ssh_brute(src_ip, packet)
        detect_http_brute(src_ip, packet)
        detect_dns_tunnel(src_ip, packet)

    # ARP runs separately (no IP layer)
    detect_arp_spoof(packet)

# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
def main():
    setup_logs()
    print("\n[*] IDS Started — Monitoring for 7 attack types:")
    print("    1. Port Scan       4. SSH Brute Force")
    print("    2. SYN Flood       5. HTTP Brute Force")
    print("    3. ICMP Flood      6. ARP Spoofing")
    print("                       7. DNS Tunneling\n")
    sniff(count=PACKET_COUNT, prn=process_packet, store=False)
    print(f"\n[+] Capture complete. Check {ALERT_FILE} for alerts.")

if __name__ == "__main__":
    main()
