import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk

def show_image(image_path, label):
    img = Image.open(image_path)
    img = img.resize((300, 300))  # Resize image to fit in the label
    img = ImageTk.PhotoImage(img)
    label.config(image=img)
    label.image = img  # Keep a reference to avoid garbage collection

def start_monitoring():
    # Placeholder for starting the monitoring process
    status_label.config(text="Monitoring...")

def stop_monitoring():
    # Placeholder for stopping the monitoring process
    status_label.config(text="Stopped")
    
def notify_user(message):
    messagebox.showwarning("Alert", message)
    status_label.config(text=message, fg='red')

# Create the main window
root = tk.Tk()
root.title("Network Traffic Monitor")

# Main Area for displaying PCAP Images
image_label = tk.Label(root)
image_label.pack(pady=10)

# Status Bar
status_label = tk.Label(root, text="Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

# Control Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Monitoring", command=start_monitoring)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(button_frame, text="Stop Monitoring", command=stop_monitoring)
stop_button.pack(side=tk.LEFT, padx=5)

exit_button = tk.Button(button_frame, text="Exit", command=root.quit)
exit_button.pack(side=tk.LEFT, padx=5)

# Example of how to update UI with an image and a notification
show_image("eximg.png", image_label)
notify_user("Malware detected!")

# Start the GUI event loop
root.mainloop()
