from scapy.all import sniff, IP, TCP, Ether
import numpy as np
import tensorflow as tf
import time
from elasticsearch import Elasticsearch
from datetime import datetime
import psutil
import socket

# -------------------- Configuration -------------------- #

# Load your trained model
MODEL_PATH = "./models/cnn_model_20241006-223656.keras"

# Elasticsearch configuration
ELASTIC_HOST = 'localhost'
ELASTIC_PORT = 9200
CLASSIFICATION_INDEX = "classification-results"
RAW_PACKET_INDEX = "raw-packet-data"
PROCESS_INFORMATION_INDEX = "process-info"

# Session management
SESSION_TIMEOUT = 5  # Seconds
PACKET_LIMIT_PER_SESSION = 1000  # Prevent excessive memory usage

# Network interface
NETWORK_INTERFACE = 'Ethernet'  # Replace with your actual interface

# -------------------- Initialization -------------------- #

# Load the trained CNN model
model = tf.keras.models.load_model(MODEL_PATH)

# Initialize counters
mal_count = 0
nor_count = 0

# Initialize Elasticsearch client
es = Elasticsearch([{'host': ELASTIC_HOST, 'port': ELASTIC_PORT, 'scheme': 'http'}])

# Dictionary to hold ongoing sessions
packet_sessions = {}


# -------------------- Helper Functions -------------------- #

def get_hostname():
    """Retrieve the hostname of the machine."""
    return socket.gethostname()

def get_mac_address(interface_name):
    """Retrieve the MAC address for the specified network interface."""
    addrs = psutil.net_if_addrs()
    if interface_name in addrs:
        for addr in addrs[interface_name]:
            if addr.family == psutil.AF_LINK:  # MAC address family
                return addr.address
    return None

def get_process_by_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            pid = conn.pid
            process = psutil.Process(pid) if pid else None
            if process:
                return process.name(), process.exe(), process.pid
    return None

def send_process_info(session_key, process_info):
    """Sends process information to Elasticsearch."""
    process_index = "process-info-index"  # Define your new index for process info
    event = {
        "timestamp": datetime.utcnow(),
        "src_port": session_key[2],
        "dst_port": session_key[3],
        "protocol": session_key[4],
        "process_name": process_info[0],
        "executable_path": process_info[1],
        "pid": process_info[2]
    }
    
    try:
        es.index(index=PROCESS_INFORMATION_INDEX, document=event)
        # print(f"Process info sent to Elasticsearch: {event}")
    except Exception as e:
        print(f"Failed to send process info to Elasticsearch: {e}")


def get_session_key(packet):
    """Extracts a unique session key from a packet."""
    src = packet[IP].src
    dst = packet[IP].dst
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    proto = packet[IP].proto
    return (src, dst, sport, dport, proto)


def anonymize_packet_for_image(packet):
    """Anonymizes packet data solely for image generation."""
    pkt = packet.copy()
    if IP in pkt:
        pkt[IP].src = "0.0.0.0"
        pkt[IP].dst = "0.0.0.0"
    if Ether in pkt:
        pkt[Ether].src = "00:00:00:00:00:00"
        pkt[Ether].dst = "00:00:00:00:00:00"
    return pkt


def send_classification_event(session_key, classification, details, additional_fields=None):
    """Sends classification results to Elasticsearch."""
    # print("src_ip: " + session_key[0] + "  type: " + str(type(session_key[0])))
    hostname = get_hostname()
    mac_address = get_mac_address(NETWORK_INTERFACE)
    event = {
        "timestamp": datetime.utcnow(),
        "session_key": f"{session_key}",
        "classification": classification,
        "details": details,
        "src_ip": session_key[0],
        "dst_ip": session_key[1],
        "src_port": session_key[2],
        "dst_port": session_key[3],
        "protocol": session_key[4],
        "hostname": hostname,
        "mac_address": mac_address
    }
    if additional_fields:
        event.update(additional_fields)
    try:
        es.index(index=CLASSIFICATION_INDEX, document=event, pipeline="geoip-pipeline")
        print(f"Classification event sent to Elasticsearch: {event}")
    except Exception as e:
        print("", end="")
        print(f"Failed to send classification event to Elasticsearch: {e}")


def send_raw_packet_event(packet_info):
    """Sends raw packet metadata to Elasticsearch."""
    event = {
        "timestamp": datetime.utcnow(),
        "session_key": packet_info.get("session_key"),
        "packet_number": packet_info.get("packet_number"),
        "src_ip": packet_info.get("src_ip"),
        "dst_ip": packet_info.get("dst_ip"),
        "src_port": packet_info.get("src_port"),
        "dst_port": packet_info.get("dst_port"),
        "protocol": packet_info.get("protocol"),
        "flags": packet_info.get("flags"),
        "length": packet_info.get("length"),
        "additional_info": packet_info.get("additional_info")
    }
    try:
        es.index(index=RAW_PACKET_INDEX, document=event, pipeline="geoip-pipeline")
        # print(f"Raw packet data sent to Elasticsearch: Session {event['session_key']}, Packet {event['packet_number']}")
    except Exception as e:
        print("", end="")
        # print(f"Failed to send raw packet data to Elasticsearch: {e}")



def process_session_packets(session_packets, session_key):
    """Processes complete session packets for classification."""
    global nor_count, mal_count

    # Anonymize packets for image generation only
    anonymized_packets = [anonymize_packet_for_image(pkt) for pkt in session_packets]

    # Prepare image array
    img_array = []
    for pkt in anonymized_packets:
        payload = bytes(pkt[TCP].payload)
        img_data = np.frombuffer(payload[:784], dtype=np.uint8)

        # Pad or trim to ensure length is exactly 784 bytes
        if len(img_data) < 784:
            img_data = np.pad(img_data, (0, 784 - len(img_data)), 'constant')
        elif len(img_data) > 784:
            img_data = img_data[:784]

        img_array.append(img_data)

    if len(img_array) == 0:
        # print(f"No payload data available for session: {session_key}. Skipping classification.")
        return

    # Convert to numpy array
    img_array = np.array(img_array)  # Shape: (n, 784)

    # Reshape and convert to RGB
    img_array = img_array.reshape(-1, 28, 28, 1)
    img_array = np.concatenate([img_array, img_array, img_array], axis=-1)  # Shape: (n, 28, 28, 3)

    # Normalize
    img_array = img_array / 255.0

    # Make predictions
    predictions = model.predict(img_array)
    average_prediction = float(np.mean(predictions))

    # Classification decision
    if average_prediction > 0.8:
        nor_count += 1
        classification = "Normal"
        # print(f"Normal traffic detected for session: {session_key}.")
    else:
        mal_count += 1
        classification = "Malicious (Neris)"
        # print(f"Malicious (Neris) traffic detected for session: {session_key}!")

        src_port = session_key[2]  # Extract the source port from session_key tuple
        process_info = get_process_by_port(src_port)
        
        if process_info:
            process_name, executable_path, pid = process_info
            print(f"Process Name: {process_name}, Executable Path: {executable_path}, PID: {pid}")
            send_process_info(session_key, process_info)
        else:
            print("No process found associated with this port.")

    print(f"Normal: {nor_count}, Malicious: {mal_count}")

    # Prepare details
    details = {
        "session_packets_count": len(session_packets)
    }

    # Additional fields (customize as needed)
    additional_fields = {}

    # Send classification event to Elasticsearch
    send_classification_event(session_key, classification, details, additional_fields)


def process_packet(packet):
    """Processes each captured packet."""
    global packet_sessions

    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Extract session key
        session_key = get_session_key(packet)

        # Initialize session if it doesn't exist
        if session_key not in packet_sessions:
            packet_sessions[session_key] = {
                'packets': [],
                'last_time': time.time(),
                'packet_count': 0
            }
            # print(f"New session created: {session_key}")

        # Add packet to session
        packet_sessions[session_key]['packets'].append(packet)
        packet_sessions[session_key]['last_time'] = time.time()
        packet_sessions[session_key]['packet_count'] += 1
        packet_number = packet_sessions[session_key]['packet_count']

        # Prepare raw packet metadata (excluding payload)
        packet_info = {
            "session_key": f"{session_key}",
            "packet_number": packet_number,
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "src_port": packet[TCP].sport,
            "dst_port": packet[TCP].dport,
            "protocol": "TCP",
            "flags": str(packet[TCP].flags),
            "length": len(packet[TCP].payload),
            "additional_info": {
                "window_size": packet[TCP].window,
                "options": [opt[0] for opt in packet[TCP].options]  # Extracting option names
            }
        }

        # Send raw packet metadata to Elasticsearch
        send_raw_packet_event(packet_info)

        # Enforce packet limit per session to prevent memory issues
        if packet_sessions[session_key]['packet_count'] >= PACKET_LIMIT_PER_SESSION:
            # print(f"Packet limit reached for session: {session_key}. Processing session...")
            process_session_packets(packet_sessions[session_key]['packets'], session_key)
            del packet_sessions[session_key]
            return

        # Check for session timeout
        current_time = time.time()
        for key in list(packet_sessions.keys()):
            session_data = packet_sessions[key]
            if current_time - session_data['last_time'] > SESSION_TIMEOUT:
                # Process and classify session
                # print(f"Session timed out: {key}. Processing session...")
                process_session_packets(session_data['packets'], key)
                del packet_sessions[key]


def capture_packets(interface):
    """Starts packet sniffing on the specified network interface."""
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=process_packet, filter="tcp", store=0)


# -------------------- Main Execution -------------------- #

if __name__ == "__main__":
    capture_packets(NETWORK_INTERFACE)