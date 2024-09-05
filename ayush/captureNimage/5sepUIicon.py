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
        return None

    data = bytearray(packet_buffer)
    required_size = image_size[0] * image_size[1]

    if len(data) < required_size:
        padded_data = np.pad(np.frombuffer(data, dtype=np.uint8), (0, required_size - len(data)), 'constant')
    else:
        padded_data = np.frombuffer(data[:required_size], dtype=np.uint8)

    image_array = padded_data.reshape(image_size)
    image = Image.fromarray(image_array, 'L')
    return image

class NetworkCaptureApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Real-Time Network Traffic Visualization")

        self.packet_buffer = deque(maxlen=100000)
        self.packet_buffer_lock = threading.Lock()
        self.packet_info_lock = threading.Lock()
        self.packet_info = {}

        self.capture_thread = None
        self.stop_event = threading.Event()

        # Frame for buttons and image
        top_frame = tk.Frame(master, bg='#2E2E2E')
        top_frame.pack(fill=tk.X)

        self.start_button = tk.Button(top_frame, text="Start Capture", command=self.start_capture, bg='#444', fg='#FFF')
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = tk.Button(top_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED, bg='#444', fg='#FFF')
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Load and display the image in the top right
        self.image_icon = Image.open("D:/Programming/netrafAi/ayush/captureNimage/image.png")  # Load your image
        self.image_icon = self.image_icon.resize((100, 50), Image.LANCZOS)  # Resize to match button size
        self.image_icon_tk = ImageTk.PhotoImage(self.image_icon)
        self.image_label = tk.Label(top_frame, image=self.image_icon_tk, bg='#2E2E2E')
        self.image_label.pack(side=tk.RIGHT, padx=5, pady=5)

        # Frame for image display and packet info
        main_frame = tk.Frame(master, bg='#2E2E2E')
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.image_display = tk.Label(main_frame, bg='#000')
        self.image_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Packet info display
        self.info_label = tk.Label(main_frame, text="Packet Info: ", font=("Arial", 12), bg='#2E2E2E', fg='#FFF')
        self.info_label.pack(side=tk.RIGHT, padx=10, pady=10, anchor=tk.NE)

        self.update_interval = 100
        self.master.after(self.update_interval, self.update_image)

    def start_capture(self):
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.stop_event.clear()
            self.packet_buffer.clear()
            self.packet_info.clear()
            self.capture_thread = PacketCaptureThread(self.packet_buffer, self.stop_event, self.packet_buffer_lock, self.packet_info)
            self.capture_thread.start()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            messagebox.showinfo("Info", "Packet capture started.")

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
                if len(self.packet_buffer) >= 256 * 256:
                    image = convert_packets_to_image(self.packet_buffer)
                    if image:
                        imgtk = ImageTk.PhotoImage(image=image)
                        self.image_display.imgtk = imgtk
                        self.image_display.config(image=imgtk)

        if self.packet_info:
            with self.packet_info_lock:
                packet_info_text = (f"Source IP: {self.packet_info.get('src_ip', 'N/A')}, "
                                    f"Destination IP: {self.packet_info.get('dst_ip', 'N/A')}, "
                                    f"Protocol: {self.packet_info.get('protocol', 'N/A')}, "
                                    f"Source Port: {self.packet_info.get('src_port', 'N/A')}, "
                                    f"Destination Port: {self.packet_info.get('dst_port', 'N/A')}")
            self.info_label.config(text=f"Packet Info: {packet_info_text}")

        self.master.after(self.update_interval, self.update_image)

    def clear_image(self):
        self.image_display.config(image='')
        self.image_display.imgtk = None
        self.info_label.config(text="Packet Info: ")

    def on_close(self):
        if self.capture_thread and self.capture_thread.is_alive():
            self.stop_event.set()
            self.capture_thread.join()
        self.master.destroy()

def main():
    root = tk.Tk()
    app = NetworkCaptureApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
