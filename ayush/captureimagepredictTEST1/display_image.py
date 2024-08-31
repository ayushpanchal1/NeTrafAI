import tkinter as tk
from PIL import Image, ImageTk

def display_image(image_path):
    root = tk.Tk()
    img = Image.open(image_path)
    img = ImageTk.PhotoImage(img)
    panel = tk.Label(root, image=img)
    panel.pack(side="bottom", fill="both", expand="yes")
    root.mainloop()

if __name__ == "__main__":
    display_image('pcap_image.png')
