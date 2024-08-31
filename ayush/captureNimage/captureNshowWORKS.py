import threading
from scapy.all import sniff, Raw
from PIL import Image, ImageTk
import numpy as np
import tkinter as tk
from tkinter import messagebox
from collections import deque

class PacketCaptureThread(threading.Thread):
    def __init__(self, packet_buffer, stop_event, packet_buffer_lock, max_packets=1000):
        super().__init__()
        self.packet_buffer = packet_buffer
        self.stop_event = stop_event
        self.packet_buffer_lock = packet_buffer_lock
        self.max_packets = max_packets

    def run(self):
        sniff(prn=self.process_packet, stop_filter=self.should_stop, store=False)

    def process_packet(self, packet):
        if Raw in packet:
            raw_data = bytes(packet[Raw].load)
            with self.packet_buffer_lock:
                if len(self.packet_buffer) > self.max_packets * 1500:
                    self.packet_buffer.popleft()  # Remove oldest data
                self.packet_buffer.extend(raw_data)

    def should_stop(self, packet):
        return self.stop_event.is_set()

def convert_packets_to_image(packet_buffer, image_size=(256, 256)):
    if not packet_buffer:
        return None

    # Convert deque to bytearray
    data = bytearray(packet_buffer)
    required_size = image_size[0] * image_size[1]

    if len(data) < required_size:
        padded_data = np.pad(np.frombuffer(data, dtype=np.uint8), (0, required_size - len(data)), 'constant')
    else:
        padded_data = np.frombuffer(data[:required_size], dtype=np.uint8)

    image_array = padded_data.reshape(image_size)
    image = Image.fromarray(image_array, 'L')  # 'L' for (8-bit pixels, black and white)
    return image

class NetworkCaptureApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Real-Time Network Traffic Visualization")

        self.packet_buffer = deque(maxlen=100000)  # Use deque for thread-safe appending
        self.packet_buffer_lock = threading.Lock()

        self.capture_thread = None
        self.stop_event = threading.Event()

        self.start_button = tk.Button(master, text="Start Capture", command=self.start_capture)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(master, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.image_label = tk.Label(master)
        self.image_label.pack(pady=10)

        self.update_interval = 100  # Update every 100 milliseconds
        self.master.after(self.update_interval, self.update_image)

    def start_capture(self):
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.stop_event.clear()
            self.packet_buffer.clear()  # Clear buffer when starting a new capture
            self.capture_thread = PacketCaptureThread(self.packet_buffer, self.stop_event, self.packet_buffer_lock)
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
                image = convert_packets_to_image(self.packet_buffer)
            if image:
                imgtk = ImageTk.PhotoImage(image=image)
                self.image_label.imgtk = imgtk  # Keep a reference
                self.image_label.config(image=imgtk)
        self.master.after(self.update_interval, self.update_image)

    def clear_image(self):
        """Clears the image from the UI."""
        self.image_label.config(image='')
        self.image_label.imgtk = None

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
