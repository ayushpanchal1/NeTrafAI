import os
import numpy as np
from PIL import Image
from scapy.all import rdpcap, IP, TCP, Ether
import hashlib
import binascii

# Constants
TRIMMED_FILE_LEN = 784  # Size to which each session will be trimmed
PNG_SIZE = 28  # Size of the PNG image
MALICIOUS_INPUT_FOLDER = '../data/processed/split/neris/'  # Path for malicious PCAP files
NORMAL_INPUT_FOLDER = '../data/processed/split/normal/'  # Path for normal PCAP files
OUTPUT_SESSION_FOLDER = '../data/processed/Session/'  # Path for output session files
OUTPUT_TRIMMED_FOLDER = '../data/processed/TrimmedSession/'  # Path for trimmed files
OUTPUT_PNG_MALICIOUS_FOLDER = '../images/neris/'  # Path for PNG images for malicious PCAPs
OUTPUT_PNG_NORMAL_FOLDER = '../images/normal/'  # Path for PNG images for normal PCAPs

# Create necessary directories
os.makedirs(OUTPUT_SESSION_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_TRIMMED_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_PNG_MALICIOUS_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_PNG_NORMAL_FOLDER, exist_ok=True)

# Function to clear a directory
def clear_directory(directory):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)  # Remove file
            elif os.path.isdir(file_path):
                os.rmdir(file_path)  # Remove directory
        except Exception as e:
            print(f"Error removing {file_path}: {e}")

# Function to anonymize packets (IP and MAC)
def anonymize_packet(pkt):
    if IP in pkt:
        pkt[IP].src = "0.0.0.0"  # Anonymize source IP
        pkt[IP].dst = "0.0.0.0"  # Anonymize destination IP

    if Ether in pkt:
        pkt[Ether].src = "00:00:00:00:00:00"  # Randomize source MAC
        pkt[Ether].dst = "00:00:00:00:00:00"  # Randomize destination MAC

    return pkt

# Function to extract sessions from packets
def extract_sessions(packets):
    sessions = {}
    for pkt in packets:
        if IP in pkt and TCP in pkt:  # Only consider IP/TCP packets
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = pkt[IP].proto

            session_key1 = (src, dst, sport, dport, proto)
            session_key2 = (dst, src, dport, sport, proto)

            if session_key1 not in sessions and session_key2 not in sessions:
                sessions[session_key1] = []

            if session_key1 in sessions:
                sessions[session_key1].append(pkt)
            else:
                sessions[session_key2].append(pkt)

    return sessions

# Function to save session packets to files with incremental filenames
def save_sessions(sessions, output_folder, start_index):
    for session_key, session_packets in sessions.items():
        # Anonymize packets after extracting sessions
        for pkt in session_packets:
            anonymize_packet(pkt)

        session_file_path = os.path.join(output_folder,
                                         f"session_{start_index}.bin")
        with open(session_file_path, 'wb') as f:
            for pkt in session_packets:
                payload = bytes(pkt[TCP].payload) if TCP in pkt else b''
                f.write(payload)

        # Remove the session file if it's empty
        if os.path.getsize(session_file_path) == 0:
            os.remove(session_file_path)  # Remove empty session file
            print(f"Removed empty session file: {session_file_path}")

        start_index += 1  # Increment the index for the next session
    return start_index

# Function to remove duplicate session files
def remove_duplicate_sessions(input_folder):
    seen_hashes = set()  # Set to track seen file hashes
    files_to_remove = []  # List to track files for removal

    for session_file in os.listdir(input_folder):
        session_path = os.path.join(input_folder, session_file)

        # Read the content and calculate the hash
        with open(session_path, 'rb') as f:
            content = f.read()
            # Create a hash of the file content
            file_hash = hashlib.md5(content).hexdigest()  # Using MD5 for simplicity

            # Check if the hash is already in the set
            if file_hash in seen_hashes:
                files_to_remove.append(session_path)  # Mark duplicate for removal
            else:
                seen_hashes.add(file_hash)  # Add the hash to the set

    # Remove the marked duplicate files
    for file_path in files_to_remove:
        os.remove(file_path)  # Remove the duplicate file
        print(f"Removed duplicate session file: {file_path}")

# Function to trim session files
def trim_sessions(input_folder, output_folder):
    for session_file in os.listdir(input_folder):
        session_path = os.path.join(input_folder, session_file)
        with open(session_path, 'rb') as f:
            content = f.read()

        if len(content) > TRIMMED_FILE_LEN:
            content = content[:TRIMMED_FILE_LEN]
        elif len(content) < TRIMMED_FILE_LEN:
            content += b'\x00' * (TRIMMED_FILE_LEN - len(content))

        trimmed_path = os.path.join(output_folder, session_file)
        with open(trimmed_path, 'wb') as f:
            f.write(content)

# Function to convert trimmed session files to PNG
def convert_to_png(input_folder, output_folder):
    for session_file in os.listdir(input_folder):
        session_path = os.path.join(input_folder, session_file)
        img_array = get_matrix_from_file(session_path, PNG_SIZE)
        img = Image.fromarray(img_array, 'L')

        png_path = os.path.join(output_folder, os.path.splitext(session_file)[0] + '.png')
        img.save(png_path)

# Function to convert file contents to a matrix for image creation
def get_matrix_from_file(filename, width):
    with open(filename, 'rb') as f:
        content = f.read()
    hex_data = binascii.hexlify(content)
    array_data = np.array([int(hex_data[i:i + 2], 16) for i in range(0, len(hex_data), 2)])

    rn = len(array_data) // width
    array_data = np.reshape(array_data[:rn * width], (-1, width))
    return np.uint8(array_data)

# Main processing workflow
def process_pcap_files():
    global_index = 1  # Initialize a global index for session filenames
    for pcap_file in os.listdir(MALICIOUS_INPUT_FOLDER):
        if pcap_file.endswith('.pcap'):
            print(f"Processing {pcap_file}...")
            packets = rdpcap(os.path.join(MALICIOUS_INPUT_FOLDER, pcap_file))

            # Extract sessions
            sessions = extract_sessions(packets)

            # Clear output directories
            clear_directory(OUTPUT_SESSION_FOLDER)
            clear_directory(OUTPUT_TRIMMED_FOLDER)

            # Save sessions to binary files with incremental filenames
            global_index = save_sessions(sessions, OUTPUT_SESSION_FOLDER, global_index)

            # Remove duplicate session files
            remove_duplicate_sessions(OUTPUT_SESSION_FOLDER)

            # Trim the session files
            trim_sessions(OUTPUT_SESSION_FOLDER, OUTPUT_TRIMMED_FOLDER)

            # Convert trimmed session files to PNG images
            convert_to_png(OUTPUT_TRIMMED_FOLDER, OUTPUT_PNG_MALICIOUS_FOLDER)

    # Process normal PCAP files similarly
    for pcap_file in os.listdir(NORMAL_INPUT_FOLDER):
        if pcap_file.endswith('.pcap'):
            print(f"Processing {pcap_file}...")
            packets = rdpcap(os.path.join(NORMAL_INPUT_FOLDER, pcap_file))

            # Extract sessions
            sessions = extract_sessions(packets)

            # Clear output directories
            clear_directory(OUTPUT_SESSION_FOLDER)
            clear_directory(OUTPUT_TRIMMED_FOLDER)

            # Save sessions to binary files with incremental filenames
            global_index = save_sessions(sessions, OUTPUT_SESSION_FOLDER, global_index)

            # Remove duplicate session files
            remove_duplicate_sessions(OUTPUT_SESSION_FOLDER)

            # Trim the session files
            trim_sessions(OUTPUT_SESSION_FOLDER, OUTPUT_TRIMMED_FOLDER)

            # Convert trimmed session files to PNG images
            convert_to_png(OUTPUT_TRIMMED_FOLDER, OUTPUT_PNG_NORMAL_FOLDER)

# Execute the processing function
process_pcap_files()
print("Image generation complete.")
