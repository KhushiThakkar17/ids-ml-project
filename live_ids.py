from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
from datetime import datetime
from collections import defaultdict
import pandas as pd
import pickle
import csv
import os

# ──────────────────────────────────────────
# LOAD TRAINED ML MODEL
# ──────────────────────────────────────────
print("[*] Loading ML model...")
with open("ids_model.pkl", "rb") as f:
    model, label_encoder = pickle.load(f)
print("[+] ML model loaded!\n")

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
ALERT_FILE   = "live_alerts.csv"
PACKET_COUNT = 200

# Rule-based thresholds
PORT_SCAN_THRESHOLD  = 10
SYN_FLOOD_THRESHOLD  = 100
ICMP_FLOOD_THRESHOLD = 50
SSH_BRUTE_THRESHOLD  = 5
HTTP_BRUTE_THRESHOLD = 20
DNS_TUNNEL_THRESHOLD = 50

# Trackers
port_tracker = defaultdict(set)
syn_tracker  = defaultdict(int)
icmp_tracker = defaultdict(int)
ssh_tracker  = defaultdict(int)
http_tracker = defaultdict(int)
arp_table    = defaultdict(set)

# Stats counter
stats = {"total": 0, "attacks": 0, "normal": 0, "alerts": 0}

# ──────────────────────────────────────────
# SETUP — Create alert log file
# ──────────────────────────────────────────
def setup():
    if not os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "detection_type",
                             "src_ip", "detail", "ml_prediction"])
    print("=" * 55)
    print("   LIVE IDS — Dual Engine Active")
    print("=" * 55)
    print("   🤖 ML Engine   — Random Forest Classifier")
    print("   📏 Rule Engine — 7 Attack Pattern Rules")
    print("=" * 55 + "\n")

# ──────────────────────────────────────────
# ALERT ENGINE — Print + Save alert
# ──────────────────────────────────────────
def raise_alert(detection_type, src_ip, detail, ml_pred="rule-based"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats["alerts"] += 1
    engine = "🤖 ML" if ml_pred != "rule-based" else "📏 RULE"
    print(f"\n🚨 [{engine}] ALERT [{detection_type}]")
    print(f"   IP     : {src_ip}")
    print(f"   Detail : {detail}")
    print(f"   Time   : {timestamp}\n")
    with open(ALERT_FILE, "a", newline="") as f:
        csv.writer(f).writerow([timestamp, detection_type,
                                src_ip, detail, ml_pred])

# ──────────────────────────────────────────
# ML PREDICTION ENGINE
# Uses trained Random Forest to classify
# each packet as 'attack' or 'normal'
# ──────────────────────────────────────────
def ml_predict(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # Extract features
    if packet.haslayer(TCP):
        proto = 0
        sp    = packet[TCP].sport
        dp    = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = 1
        sp    = packet[UDP].sport
        dp    = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = 2
        sp    = 0
        dp    = 0
    else:
        proto = 3
        sp    = 0
        dp    = 0

    size = len(packet)

    # Build DataFrame with feature names (fixes warning)
    features = pd.DataFrame(
        [[proto, sp, dp, size]],
        columns=["protocol_enc", "src_port", "dst_port", "size"]
    )

    # Predict
    prediction  = model.predict(features)[0]
    confidence  = model.predict_proba(features).max() * 100

    stats["total"] += 1

    if prediction == "attack":
        stats["attacks"] += 1
        raise_alert(
            "ML DETECTED ATTACK",
            src_ip,
            f"Confidence: {confidence:.1f}% | "
            f"proto={proto} sp={sp} dp={dp} size={size}",
            ml_pred=f"attack ({confidence:.1f}%)"
        )
    else:
        stats["normal"] += 1

# ──────────────────────────────────────────
# RULE ENGINE — ARP Spoof (needs own func
# because it has no IP layer)
# ──────────────────────────────────────────
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip  = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        arp_table[src_ip].add(src_mac)
        if len(arp_table[src_ip]) > 1:
            raise_alert(
                "ARP SPOOFING",
                src_ip,
                f"Multiple MACs claiming same IP: {arp_table[src_ip]}"
            )

# ──────────────────────────────────────────
# RULE ENGINE — All 7 attack rules
# ──────────────────────────────────────────
def rule_based_detect(packet):

    # ARP runs without IP layer
    detect_arp_spoof(packet)

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # ── Rule 1: Port Scan ──
    if packet.haslayer(TCP):
        port_tracker[src_ip].add(packet[TCP].dport)
        if len(port_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            raise_alert(
                "PORT SCAN", src_ip,
                f"Touched {len(port_tracker[src_ip])} unique ports"
            )
            port_tracker[src_ip].clear()

    # ── Rule 2: SYN Flood ──
    if packet.haslayer(TCP) and packet[TCP].flags == 0x02:
        syn_tracker[src_ip] += 1
        if syn_tracker[src_ip] >= SYN_FLOOD_THRESHOLD:
            raise_alert(
                "SYN FLOOD", src_ip,
                f"{syn_tracker[src_ip]} SYN packets detected"
            )
            syn_tracker[src_ip] = 0

    # ── Rule 3: ICMP Flood ──
    if packet.haslayer(ICMP):
        icmp_tracker[src_ip] += 1
        if icmp_tracker[src_ip] >= ICMP_FLOOD_THRESHOLD:
            raise_alert(
                "ICMP FLOOD", src_ip,
                f"{icmp_tracker[src_ip]} ICMP packets detected"
            )
            icmp_tracker[src_ip] = 0

    # ── Rule 4: SSH Brute Force ──
    if packet.haslayer(TCP) and \
       packet[TCP].dport == 22 and \
       packet[TCP].flags == 0x02:
        ssh_tracker[src_ip] += 1
        if ssh_tracker[src_ip] >= SSH_BRUTE_THRESHOLD:
            raise_alert(
                "SSH BRUTE FORCE", src_ip,
                f"{ssh_tracker[src_ip]} SSH connection attempts"
            )
            ssh_tracker[src_ip] = 0

    # ── Rule 5: HTTP Brute Force ──
    if packet.haslayer(TCP) and \
       packet[TCP].dport in [80, 443, 8080]:
        http_tracker[src_ip] += 1
        if http_tracker[src_ip] >= HTTP_BRUTE_THRESHOLD:
            raise_alert(
                "HTTP BRUTE FORCE", src_ip,
                f"{http_tracker[src_ip]} HTTP requests detected"
            )
            http_tracker[src_ip] = 0

    # ── Rule 6: DNS Tunneling ──
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode(errors="ignore")
        if len(query) > DNS_TUNNEL_THRESHOLD:
            raise_alert(
                "DNS TUNNELING", src_ip,
                f"Long DNS query ({len(query)} chars): {query[:40]}..."
            )

# ──────────────────────────────────────────
# MAIN PACKET PROCESSOR
# Runs on every captured packet
# ──────────────────────────────────────────
def process_packet(packet):
    if packet.haslayer(IP):
        src  = packet[IP].src
        dst  = packet[IP].dst
        size = len(packet)
        print(f"[PACKET] {src} → {dst} | {size} bytes")

    # Run both engines
    ml_predict(packet)
    rule_based_detect(packet)

    # Print live stats every 20 packets
    if stats["total"] > 0 and stats["total"] % 20 == 0:
        print(f"\n📊 Stats | Total: {stats['total']} | "
              f"Attacks: {stats['attacks']} | "
              f"Normal: {stats['normal']} | "
              f"Alerts: {stats['alerts']}\n")

# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
def main():
    setup()
    print(f"[*] Capturing {PACKET_COUNT} packets...\n")
    sniff(count=PACKET_COUNT, prn=process_packet, store=False)

    # Final report
    print(f"\n{'='*55}")
    print(f"   📊 FINAL REPORT")
    print(f"{'='*55}")
    print(f"   Total Packets  : {stats['total']}")
    print(f"   Attacks Found  : {stats['attacks']}")
    print(f"   Normal Traffic : {stats['normal']}")
    print(f"   Total Alerts   : {stats['alerts']}")
    print(f"   Alerts saved   : {ALERT_FILE}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    main()
