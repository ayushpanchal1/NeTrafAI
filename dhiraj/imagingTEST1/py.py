from scapy.all import rdpcap, IP
from PIL import Image
import numpy as np
import os

# Constants
IMAGE_SIZE = 50  # 50x50 pixels
CHANNELS = 3  # RGB

def extract_sessions(pcap_file):
    """Extract sessions from a PCAP file using scapy."""
    print(f"Opening PCAP file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return {}
    
    sessions = {}
    print(f"Total packets in file: {len(packets)}")

    try:
        for packet in packets:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                session_key = (src, dst)
                if session_key not in sessions:
                    sessions[session_key] = []
                sessions[session_key].append(packet)
    except Exception as e:
        print(f"Error while processing packets: {e}")
    
    print(f"Extracted {len(sessions)} sessions.")
    return sessions

def packet_to_image(packets):
    """Convert a list of packets to a 50x50 RGB image."""
    print(f"Converting {len(packets)} packets to image.")
    image_data = np.zeros((IMAGE_SIZE, IMAGE_SIZE, CHANNELS), dtype=np.uint8)
    
    for i, packet in enumerate(packets[:IMAGE_SIZE]):
        if IP in packet:
            try:
                tos = int(packet[IP].tos)  # Ensure TOS is an integer
                total_length = int(packet[IP].len)  # Ensure total length is an integer
                ttl = int(packet[IP].ttl)  # Ensure TTL is an integer
                
                # Map fields to colors
                red = tos % 256
                green = total_length % 256
                blue = ttl % 256

                # Debugging outputs
                print(f"Packet {i}: TOS={tos}, Total Length={total_length}, TTL={ttl}")
                print(f"Assigned colors: R={red}, G={green}, B={blue}")
                
                image_data[i, :, 0] = red
                image_data[i, :, 1] = green
                image_data[i, :, 2] = blue
            except Exception as e:
                print(f"Error while processing packet {i}: {e}")
    
    # Handle cases where there are fewer than IMAGE_SIZE packets
    if len(packets) < IMAGE_SIZE:
        print(f"Padding image as there are only {len(packets)} packets.")
        image_data = pad_image(image_data)
    
    print(f"Image conversion complete. Image shape: {image_data.shape}")
    return image_data

def pad_image(image_data, max_packets=IMAGE_SIZE):
    """Pad the image with black rows if the number of packets is less than IMAGE_SIZE."""
    if image_data.shape[0] < max_packets:
        padding = np.zeros((max_packets - image_data.shape[0], image_data.shape[1], image_data.shape[2]), dtype=np.uint8)
        image_data = np.vstack([image_data, padding])
    return image_data

def save_image(image_data, filename):
    """Save the image data to a file."""
    print(f"Saving image to {filename}")
    try:
        img = Image.fromarray(image_data)
        img.save(filename)
        print(f"Image saved successfully.")
    except Exception as e:
        print(f"Error saving image: {e}")

def main(pcap_file, output_dir):
    print(f"Starting processing for PCAP file: {pcap_file}")
    sessions = extract_sessions(pcap_file)
    
    if not sessions:
        print("No sessions extracted. Exiting.")
        return
    
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    session_count = 0
    for session_key, packets in sessions.items():
        print(f"Processing session: {session_key}")
        image_data = packet_to_image(packets)
        output_image_file = os.path.join(output_dir, f"session_{session_count}.png")
        save_image(image_data, output_image_file)
        print(f"Image for session {session_key} saved to {output_image_file}")
        session_count += 1

if __name__ == "__main__":
    # Example usage
    pcap_file = "./Dataset/small2.pcap"  # Replace with your PCAP file path
    output_dir = "./output_images2"  # Directory to save images
    main(pcap_file, output_dir)