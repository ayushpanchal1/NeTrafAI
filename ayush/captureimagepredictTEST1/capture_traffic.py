from scapy.all import sniff, wrpcap

def capture_traffic(pcap_filename='captured.pcap'):
    def packet_callback(packet):
        wrpcap(pcap_filename, packet, append=True)

    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    capture_traffic()
