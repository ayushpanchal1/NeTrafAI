from scapy.all import sniff, IP, TCP, Ether
import numpy as np
import tensorflow as tf
import time

# Load your trained model
model = tf.keras.models.load_model("./models/cnn_model_20241006-223656.keras")

mal_count = 0
nor_count = 0

# Constants
SESSION_TIMEOUT = 5  # Seconds to wait before considering session complete
packet_sessions = {}  # Dictionary to hold ongoing sessions

# Function to extract the session key from a packet
def get_session_key(packet):
    src = packet[IP].src
    dst = packet[IP].dst
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    proto = packet[IP].proto
    return (src, dst, sport, dport, proto)

# Function to anonymize packets (IP and MAC)
def anonymize_packets(session_packets):
    for pkt in session_packets:
        if IP in pkt:
            pkt[IP].src = "0.0.0.0"  # Anonymize source IP
            pkt[IP].dst = "0.0.0.0"  # Anonymize destination IP
        if Ether in pkt:
            pkt[Ether].src = "00:00:00:00:00:00"  # Randomize source MAC
            pkt[Ether].dst = "00:00:00:00:00:00"  # Randomize destination MAC
    return session_packets

# Function to process packets and maintain sessions
def process_packet(packet):
    global packet_sessions

    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Extract session key
        session_key = get_session_key(packet)

        # Initialize the session if it doesn't exist
        if session_key not in packet_sessions:
            packet_sessions[session_key] = {'packets': [], 'last_time': time.time()}
            # print(f"New session created: {session_key}")

        # Add the packet to the session
        packet_sessions[session_key]['packets'].append(packet)
        packet_sessions[session_key]['last_time'] = time.time()
        # print(f"Packet added to session {session_key}. Total packets in session: {len(packet_sessions[session_key]['packets'])}")

        # Check for session completion and timeout
        for key in list(packet_sessions.keys()):
            session_data = packet_sessions[key]
            # If the session has timed out, process the packets
            if time.time() - session_data['last_time'] > SESSION_TIMEOUT:
                # print(f"Session timed out: {session_key}. Processing session...")
                process_session_packets(session_data['packets'], key)
                del packet_sessions[key]  # Remove the session after processing

# Function to process complete session packets
def process_session_packets(session_packets, session_key):
    global nor_count, mal_count
    # Anonymize the packets after forming the session
    session_packets = anonymize_packets(session_packets)

    # Prepare to create an image from session packets
    img_array = []

    for pkt in session_packets:
        payload = bytes(pkt[TCP].payload)
        img_data = np.frombuffer(payload[:784], dtype=np.uint8)

        # Pad or trim to ensure length is exactly 784 bytes
        if len(img_data) < 784:
            img_data = np.pad(img_data, (0, 784 - len(img_data)), 'constant')  # Pad to 784
        elif len(img_data) > 784:
            img_data = img_data[:784]  # Trim to 784

        img_array.append(img_data)

    # Convert to a complete image for CNN prediction
    if len(img_array) > 0:
        img_array = np.array(img_array)  # Shape will be (n, 784)

        # Convert to RGB by stacking the grayscale image across 3 channels
        img_array = img_array.reshape(-1, 28, 28, 1)  # Reshape to (n, 28, 28, 1)

        # Convert to RGB by duplicating the grayscale channel
        img_array = np.concatenate([img_array, img_array, img_array], axis=-1)  # Shape will be (n, 28, 28, 3)

        # Normalize
        img_array = img_array / 255.0

        # Make predictions
        predictions = model.predict(img_array)
        for prediction in predictions:
            if prediction > 0.5:
                nor_count += 1
                print(f"Normal traffic detected for session: {session_key}.")
                print(f"Normal: {nor_count}, Malicious: {mal_count}")
            else:
                mal_count += 1
                print(f"Malicious (Neris) traffic detected for session: {session_key}!")
                print(f"Normal: {nor_count}, Malicious: {mal_count}")

# Real-time packet sniffing
def capture_packets(interface):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=process_packet, filter="tcp", store=0)

# Start capturing packets from a specific network interface (like Ethernet)
capture_packets('Ethernet')  # Replace 'Ethernet' with your actual network interface name
