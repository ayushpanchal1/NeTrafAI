from scapy.all import sniff, DNSQR
import tldextract

# Function to handle each packet
def process_packet(packet):
    if packet.haslayer(DNSQR):  # Check if the packet has a DNS query request
        full_domain = packet[DNSQR].qname.decode('utf-8')
        extracted = tldextract.extract(full_domain)
        core_domain = extracted.domain  # Extract only the core domain name
        print(f"Core Domain: {core_domain}")

# Sniff DNS packets on the 'eth0' interface (you can change 'eth0' to the relevant interface)
sniff(filter="udp port 53", prn=process_packet, iface="Ethernet", store=0)
