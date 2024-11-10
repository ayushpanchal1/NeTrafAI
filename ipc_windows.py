from scapy.all import sniff, IP, TCP, Ether
import numpy as np
import tensorflow as tf
import time
import socket
import json
from win10toast import ToastNotifier

# Notifications
toaster = ToastNotifier()
malicious_session_counts = {}  # session_key_str: (count, notification_sent)
MALICIOUS_THRESHOLD = 30  # Adjust as needed


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
            pkt[Ether].src = "00:00:00:00:00:00"  # Anonymize source MAC
            pkt[Ether].dst = "00:00:00:00:00:00"  # Anonymize destination MAC
    return session_packets

# Function to send messages to the GUI's socket server
def send_message(message):
    HOST = 'localhost'  # The server's hostname or IP address
    PORT = 65432        # The port used by the server

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(message.encode('utf-8'))
            print(f"Sent message: {message}")
    except ConnectionRefusedError:
        print("Failed to connect to the GUI. Ensure the GUI is running and listening on the correct port.")

# Function to process complete session packets
def process_session_packets(session_packets, session_key):
    global nor_count, mal_count, malicious_session_counts
    # Anonymize the packets after forming the session
    session_packets = anonymize_packets(session_packets)
    session_key_str = str(session_key)

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
        img_array = np.concatenate([img_array, img_array, img_array], axis=-1)  # Shape (n, 28, 28, 3)

        # Normalize
        img_array = img_array / 255.0

        # Make predictions
        predictions = model.predict(img_array)
        for prediction in predictions:
            if prediction > 0.5:
                nor_count += 1
                message = {
                    "type": "normal",
                    "session_key": session_key,
                    "nor_count": nor_count,
                    "mal_count": mal_count,
                    "text": f"Normal traffic detected for session: {session_key}."
                }
            else:
                mal_count += 1
                message = {
                    "type": "malicious",
                    "session_key": session_key,
                    "nor_count": nor_count,
                    "mal_count": mal_count,
                    "text": f"Malicious (Neris) traffic detected for session: {session_key}!"
                }
                count, notification_sent = malicious_session_counts.get(session_key_str, (0, False))
                count += 1
                malicious_session_counts[session_key_str] = (count, notification_sent)
                if count >= MALICIOUS_THRESHOLD and not notification_sent:
                    # Send Windows notification
                    notification_title = "Malicious Traffic Alert"
                    notification_message = f"Session {session_key} has reached {count} malicious events."
                    toaster.show_toast(notification_title, notification_message, duration=10)
                    # Update notification_sent to True
                    malicious_session_counts[session_key_str] = (count, True)

            # Convert message to JSON and send
            message_json = json.dumps(message)
            send_message(message_json)
            print(f"Message to be sent: {message_json}")

# Function to process packets and maintain sessions
def process_packet(packet):
    global packet_sessions

    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Extract session key
        session_key = get_session_key(packet)

        # Initialize the session if it doesn't exist
        if session_key not in packet_sessions:
            packet_sessions[session_key] = {'packets': [], 'last_time': time.time()}

        # Add the packet to the session
        packet_sessions[session_key]['packets'].append(packet)
        packet_sessions[session_key]['last_time'] = time.time()

        # Check for session completion and timeout
        keys_to_process = []
        current_time = time.time()
        for key, session_data in packet_sessions.items():
            if current_time - session_data['last_time'] > SESSION_TIMEOUT:
                keys_to_process.append(key)

        for key in keys_to_process:
            session_data = packet_sessions.pop(key)
            process_session_packets(session_data['packets'], key)

# Real-time packet sniffing
def capture_packets(interface):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=lambda pkt: process_packet(pkt), filter="tcp", store=0)
    print(f"Packet capture on interface {interface} stopped.")

if __name__ == "__main__":
    # capture_packets("wlp1s0")
    capture_packets("Ethernet")
