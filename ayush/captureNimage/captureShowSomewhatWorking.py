import threading
import time
from scapy.all import sniff, Raw
from PIL import Image, ImageTk
import numpy as np
import tkinter as tk
from tkinter import messagebox
import io

class PacketCaptureThread(threading.Thread):
    def __init__(self, packet_buffer, stop_event, max_packets=1000):
        super().__init__()
        self.packet_buffer = packet_buffer
        self.stop_event = stop_event
        self.max_packets = max_packets

    def run(self):
        sniff(prn=self.process_packet, stop_filter=self.should_stop, store=False)

    def process_packet(self, packet):
        if Raw in packet:
            raw_data = bytes(packet[Raw].load)
            self.packet_buffer.extend(raw_data)
            # Limit the buffer size to prevent excessive memory usage
            if len(self.packet_buffer) > self.max_packets * 1500:  # Assuming max 1500 bytes per packet
                del self.packet_buffer[:self.max_packets // 2]

    def should_stop(self, packet):
        return self.stop_event.is_set()

def convert_packets_to_image(packet_buffer, image_size=(256, 256)):
    """
    Converts packet byte data to a grayscale image.
    """
    if not packet_buffer:
        return None

    # Convert the byte buffer to a NumPy array
    data = np.frombuffer(packet_buffer, dtype=np.uint8)

    # Normalize data to fit the image size
    required_size = image_size[0] * image_size[1]
    if len(data) < required_size:
        # Pad with zeros if data is less than required
        padded_data = np.pad(data, (0, required_size - len(data)), 'constant')
    else:
        # Truncate data if it's more than required
        padded_data = data[:required_size]

    # Reshape to 2D array
    image_array = padded_data.reshape(image_size)

    # Create a PIL image
    image = Image.fromarray(image_array, 'L')  # 'L' for (8-bit pixels, black and white)

    return image

class NetworkCaptureApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Real-Time Network Traffic Visualization")

        # Packet buffer to store raw bytes
        self.packet_buffer = bytearray()

        # Thread control
        self.capture_thread = None
        self.stop_event = threading.Event()

        # UI Elements
        self.start_button = tk.Button(master, text="Start Capture", command=self.start_capture)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(master, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Image display
        self.image_label = tk.Label(master)
        self.image_label.pack(pady=10)

        # Update image periodically
        self.update_interval = 2000  # in milliseconds
        self.master.after(self.update_interval, self.update_image)

    def start_capture(self):
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.stop_event.clear()
            self.capture_thread = PacketCaptureThread(self.packet_buffer, self.stop_event)
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
            messagebox.showinfo("Info", "Packet capture stopped.")

    def update_image(self):
        if self.packet_buffer:
            image = convert_packets_to_image(self.packet_buffer)
            if image:
                # Convert PIL image to ImageTk
                imgtk = ImageTk.PhotoImage(image=image)
                self.image_label.imgtk = imgtk  # Keep a reference
                self.image_label.config(image=imgtk)
        # Schedule the next update
        self.master.after(self.update_interval, self.update_image)

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
