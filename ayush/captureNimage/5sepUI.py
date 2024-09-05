import threading
from scapy.all import sniff, Raw, IP, TCP, UDP
from PIL import Image, ImageTk
import numpy as np
import tkinter as tk
from tkinter import messagebox
from collections import deque

class PacketCaptureThread(threading.Thread):
    def __init__(self, packet_buffer, stop_event, packet_buffer_lock, packet_info, max_packets=1000):
        super().__init__()
        self.packet_buffer = packet_buffer
        self.stop_event = stop_event
        self.packet_buffer_lock = packet_buffer_lock
        self.max_packets = max_packets
        self.packet_info = packet_info
        self.packet_info_lock = threading.Lock()

    def run(self):
        sniff(prn=self.process_packet, stop_filter=self.should_stop, store=False)

    def process_packet(self, packet):
        if Raw in packet:
            raw_data = bytes(packet[Raw].load)
            with self.packet_buffer_lock:
                if len(self.packet_buffer) > self.max_packets * 1500:
                    self.packet_buffer.popleft()  # Remove oldest data
                self.packet_buffer.extend(raw_data)
                print(f"Packet buffer size: {len(self.packet_buffer)} bytes")  # Debugging line

            # Extract IP and port information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"

                # Update packet_info with this data
                with self.packet_info_lock:
                    self.packet_info['src_ip'] = src_ip
                    self.packet_info['dst_ip'] = dst_ip
                    self.packet_info['protocol'] = protocol
                    self.packet_info['src_port'] = src_port
                    self.packet_info['dst_port'] = dst_port

    def should_stop(self, packet):
        return self.stop_event.is_set()

def convert_packets_to_image(packet_buffer, image_size=(256, 256)):
    if not packet_buffer:
        print("No data in buffer to create image")  # Debugging line
        return None

    data = bytearray(packet_buffer)
    required_size = image_size[0] * image_size[1]

    if len(data) < required_size:
        padded_data = np.pad(np.frombuffer(data, dtype=np.uint8), (0, required_size - len(data)), 'constant')
    else:
        padded_data = np.frombuffer(data[:required_size], dtype=np.uint8)

    print(f"Generating image with {len(padded_data)} bytes of data")  # Debugging line

    image_array = padded_data.reshape(image_size)
    image = Image.fromarray(image_array, 'L')  # 'L' for (8-bit pixels, black and white)
    return image

class NetworkCaptureApp:
    def __init__(self, master):
        self.master = master
        self.master.title("NetTrafAI")

        # Dark theme
        self.master.configure(bg="#2e2e2e")
        self.button_color = "#444444"
        self.text_color = "#ffffff"
        self.info_color = "#eeeeee"

        self.packet_buffer = deque(maxlen=100000)
        self.packet_buffer_lock = threading.Lock()
        self.packet_info_lock = threading.Lock()
        self.packet_info = {}

        self.capture_thread = None
        self.stop_event = threading.Event()

        # Frame for buttons
        self.button_frame = tk.Frame(master, bg="#2e2e2e")
        self.button_frame.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.start_button = tk.Button(self.button_frame, text="Start Capture", command=self.start_capture, bg=self.button_color, fg=self.text_color)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED, bg=self.button_color, fg=self.text_color)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Frame for image and info
        self.main_frame = tk.Frame(master, bg="#2e2e2e")
        self.main_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # Frame for image
        self.image_frame = tk.Frame(self.main_frame, bg="#2e2e2e")
        self.image_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.image_label = tk.Label(self.image_frame, bg="#2e2e2e")
        self.image_label.pack(pady=10)

        # Frame for packet info
        self.info_frame = tk.Frame(self.main_frame, bg="#2e2e2e")
        self.info_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        self.info_label = tk.Label(self.info_frame, text="Packet Info: ", font=("Arial", 12), bg="#2e2e2e", fg=self.info_color, justify="left", anchor="nw")
        self.info_label.pack(pady=5)

        self.update_interval = 100
        self.master.after(self.update_interval, self.update_image)

        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure(1, weight=1)

    def start_capture(self):
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.stop_event.clear()
            self.packet_buffer.clear()  # Clear buffer when starting a new capture
            self.packet_info.clear()  # Clear packet info
            self.capture_thread = PacketCaptureThread(self.packet_buffer, self.stop_event, self.packet_buffer_lock, self.packet_info)
            self.capture_thread.start()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            messagebox.showinfo("Info", "Packet capture started.")
        else:
            print("Capture thread is already running.")  # Debugging line

    def stop_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            self.stop_event.set()
            self.capture_thread.join()
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.clear_image()
            messagebox.showinfo("Info", "Packet capture stopped.")

    def update_image(self):
        if self.packet_buffer:
            with self.packet_buffer_lock:
                # Only generate image if there is enough data
                if len(self.packet_buffer) >= 256 * 256:  # Ensure there's enough data for the image
                    image = convert_packets_to_image(self.packet_buffer)
                    if image:
                        imgtk = ImageTk.PhotoImage(image=image)
                        self.image_label.imgtk = imgtk
                        self.image_label.config(image=imgtk)

        # Update packet information
        if self.packet_info:
            with self.packet_info_lock:
                packet_info_text = (f"Source IP: {self.packet_info.get('src_ip', 'N/A')}\n"
                                    f"Destination IP: {self.packet_info.get('dst_ip', 'N/A')}\n"
                                    f"Protocol: {self.packet_info.get('protocol', 'N/A')}\n"
                                    f"Source Port: {self.packet_info.get('src_port', 'N/A')}\n"
                                    f"Destination Port: {self.packet_info.get('dst_port', 'N/A')}")
            self.info_label.config(text=f"Packet Info:\n{packet_info_text}")

        self.master.after(self.update_interval, self.update_image)

    def clear_image(self):
        """Clears the image from the UI."""
        self.image_label.config(image='')
        self.image_label.imgtk = None
        self.info_label.config(text="Packet Info: ")

    def on_close(self):
        if self.capture_thread and self.capture_thread.is_alive():
            self.stop_event.set()
            self.capture_thread.join()
        self.master.destroy()

def main():
    root = tk.Tk()
    
    # Set the window icon
    try:
        # For Windows
        root.iconbitmap("D:/Programming/netrafAi/ayush/captureNimage/icontr.ico")
        
        # For other systems (comment the line above if using this)
        # root.iconphoto(True, tk.PhotoImage(file="path_to_your_icon.png"))
        
    except Exception as e:
        print(f"Error setting icon: {e}")
    
    app = NetworkCaptureApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()

    