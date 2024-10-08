import sys
import threading
import time
from scapy.all import sniff, Raw, IP, TCP, UDP
from PIL import Image
import numpy as np
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox, QGridLayout
from PyQt5.QtGui import QPixmap, QIcon
from collections import deque, defaultdict
import os
import matplotlib
matplotlib.use('Qt5Agg')  # Use Qt5Agg backend for matplotlib
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


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
    image = Image.fromarray(image_array, 'L')  # 'L' for (8-bit pixels, black and white)
    return image


class MatplotlibCanvas(FigureCanvas):
    def __init__(self, parent=None):
        self.fig = Figure()
        self.ax = self.fig.add_subplot(111)
        super().__init__(self.fig)

    def plot(self, x_data, y_data, title, xlabel, ylabel):
        self.ax.clear()
        self.ax.plot(x_data, y_data, marker='o')
        self.ax.set_title(title)
        self.ax.set_xlabel(xlabel)
        self.ax.set_ylabel(ylabel)
        self.ax.grid()
        self.draw()


class NetworkCaptureApp(QWidget):
    def __init__(self):
        super().__init__()

        self.packet_buffer = deque(maxlen=100000)
        self.packet_buffer_lock = threading.Lock()
        self.packet_info_lock = threading.Lock()
        self.packet_info = {}
        self.packet_counts = defaultdict(int)  # To store packet counts
        self.throughput_times = deque(maxlen=10)  # To store throughput for plotting
        self.start_time = None  # To track start time for throughput calculation
        self.time_interval = 1  # Time interval for throughput calculation (in seconds)

        self.capture_thread = None
        self.stop_event = threading.Event()

        # Set up the UI layout
        self.initUI()

        # Timer for periodic updates
        self.update_interval = 100  # 100ms
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_image)
        self.timer.start(self.update_interval)

    def initUI(self):
        self.setWindowTitle("NetTrafAI")
        self.setGeometry(100, 100, 800, 600)

        # Load and set the window icon
        self.setWindowIcon(QIcon("D:/Programming/netrafAi/ayush/captureNimage/icontr.ico"))

        # Layout setup
        layout = QVBoxLayout()

        # Start/Stop buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton('Start Capture', self)
        self.start_button.clicked.connect(self.start_capture)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton('Stop Capture', self)
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)

        layout.addLayout(button_layout)

        # Image display
        self.image_label = QLabel(self)
        self.image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.image_label)

        # Packet info display
        self.info_label = QLabel("Packet Info:", self)
        layout.addWidget(self.info_label)

        # Create canvas for charts before adding to layout
        self.line_chart_canvas = MatplotlibCanvas(self)
        self.pie_chart_canvas = MatplotlibCanvas(self)

        # Create layout for charts
        chart_layout = QGridLayout()
        chart_layout.addWidget(self.pie_chart_canvas, 0, 0)
        chart_layout.addWidget(self.line_chart_canvas, 0, 1)

        layout.addLayout(chart_layout)

        # Set dark theme
        self.setStyleSheet("background-color: #2e2e2e; color: white;")

        # Set layout
        self.setLayout(layout)

    def clear_image(self):
        """Clears the displayed image and resets the image label."""
        self.image_label.clear()  # Clear the QLabel
        self.image_label.setText("No Image")  # Optional: Set a text indicating no image

    def start_capture(self):
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.stop_event.clear()
            self.packet_buffer.clear()  # Clear buffer when starting a new capture
            self.packet_info.clear()  # Clear packet info
            self.packet_counts.clear()  # Clear packet counts
            self.throughput_times.clear()  # Clear throughput times
            self.start_time = None  # Reset start time
            self.capture_thread = PacketCaptureThread(self.packet_buffer, self.stop_event, self.packet_buffer_lock, self.packet_info)
            self.capture_thread.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            QMessageBox.information(self, "Info", "Packet capture started.")

    def stop_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            self.stop_event.set()
            self.capture_thread.join()
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.clear_image()  # Clear the image when stopping capture
            QMessageBox.information(self, "Info", "Packet capture stopped.")

    def update_image(self):
        if self.packet_buffer:
            with self.packet_buffer_lock:
                if len(self.packet_buffer) >= 256 * 256:  # Ensure there's enough data for the image
                    image = convert_packets_to_image(self.packet_buffer)
                    if image:
                        # Save to a temporary file
                        temp_file_path = 'temp_image.png'
                        image.save(temp_file_path)

                        # Load the image using QPixmap
                        pixmap = QPixmap(temp_file_path)
                        self.image_label.setPixmap(pixmap)

                        # Cleanup the temporary image file
                        os.remove(temp_file_path)

        # Update packet information
        if self.packet_info:
            with self.packet_info_lock:
                packet_info_text = (f"Source IP: {self.packet_info.get('src_ip', 'N/A')}\n"
                                    f"Destination IP: {self.packet_info.get('dst_ip', 'N/A')}\n"
                                    f"Protocol: {self.packet_info.get('protocol', 'N/A')}\n"
                                    f"Source Port: {self.packet_info.get('src_port', 'N/A')}\n"
                                    f"Destination Port: {self.packet_info.get('dst_port', 'N/A')}")
            self.info_label.setText(f"Packet Info:\n{packet_info_text}")

        # Calculate throughput
        current_time = time.time()
        if self.start_time is None:
            self.start_time = current_time  # Initialize start time

        elapsed_time = current_time - self.start_time
        if elapsed_time >= self.time_interval:
            # Count packets
            packet_count = len(self.packet_buffer)
            self.packet_counts['Total Packets'] += packet_count
            self.throughput = packet_count / elapsed_time  # Calculate throughput (packets/s)
            self.throughput_times.append(self.throughput)  # Store throughput for plotting
            self.start_time = current_time  # Reset start time for the next interval

        # Update charts
        self.plot_charts()

    def plot_charts(self):
        self.plot_pie_chart()
        self.plot_line_chart()

    def plot_line_chart(self):
        # Prepare data for the line chart
        x_data = list(range(len(self.throughput_times)))
        y_data = list(self.throughput_times)
        self.line_chart_canvas.plot(x_data, y_data, 'Packet Throughput', 'Time Interval (s)', 'Throughput (packets/s)')

    def plot_pie_chart(self):
        if self.packet_counts:
            labels = list(self.packet_counts.keys())
            sizes = list(self.packet_counts.values())
            self.pie_chart_canvas.ax.clear()  # Clear previous pie chart
            self.pie_chart_canvas.ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            self.pie_chart_canvas.ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
            self.pie_chart_canvas.ax.set_title('Packet Protocol Distribution')
            self.pie_chart_canvas.draw()  # Update the pie chart


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NetworkCaptureApp()
    window.show()
    sys.exit(app.exec_())
