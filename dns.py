from scapy.all import sniff, DNSQR
import tldextract
from elasticsearch import Elasticsearch
from datetime import datetime

# -------------------- Configuration -------------------- #

ELASTIC_HOST = 'localhost'
ELASTIC_PORT = 9200
DNS_INDEX = "dns-queries"
NETWORK_INTERFACE = 'wlp1s0'

# Initialize Elasticsearch
es = Elasticsearch([{'host': ELASTIC_HOST, 'port': ELASTIC_PORT, 'scheme': 'http'}])

# Function to handle each packet
def process_packet(packet):
    if packet.haslayer(DNSQR):  # Check if the packet has a DNS query request
        full_domain = packet[DNSQR].qname.decode('utf-8')
        extracted = tldextract.extract(full_domain)
        core_domain = extracted.domain  # Extract only the core domain name
        
        # Prepare document to send to Elasticsearch
        doc = {
            'core_domain': core_domain,
            'timestamp': datetime.utcnow()
        }
        
        # Send the document to Elasticsearch
        es.index(index=DNS_INDEX, body=doc)
        print(f"Core Domain: {core_domain}")

# Sniff DNS packets on the 'eth0' interface (change 'eth0' if needed)
sniff(filter="udp port 53", prn=process_packet, iface=NETWORK_INTERFACE, store=0)