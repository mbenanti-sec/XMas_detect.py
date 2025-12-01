from scapy.all import sniff, IP, TCP

# FIN = 0x01, PSH = 0x08, URG = 0x20 -> 0x29
XMAS_MASK = 0x01 | 0x08 | 0x20  # = 0x29

def is_xmas_packet(pkt):
    """Ritorna True se il pacchetto ha i flag FIN, PSH, URG impostati"""
    if pkt.haslayer(TCP):
        flags = pkt [TCP].flags

        return (flags & XMAS_MASK) == XMAS_MASK
    return False

def detect_xmas(pkt):
    if not is_xmas_packet(pkt):
        return

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"
    dport  = pkt[TCP].dport

    print(f"[XMAS] detected XMas packet: {src_ip} -> {dst_ip}:{dport} flags={pkt[TCP].flags}")

if __name__=="__main__":
    # here change with your interface (es. eth0, enp0s3, wlan0...)
    IFACE = "eth0"

    print(f"[+] listen on {IFACE} for packet XMas (FIN+PSH+URG)...")
    sniff(
        iface=IFACE,       #web interface to use
        filter="tcp",      
        prn=detect_xmas,  
        store=0            
    )
