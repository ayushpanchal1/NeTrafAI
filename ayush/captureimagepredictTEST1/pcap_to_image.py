from PIL import Image
import pyshark
import numpy as np

def pcap_to_image(pcap_file, image_file='pcap_image.png'):
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    image_data = []

    for packet in cap:
        if hasattr(packet, 'layers'):
            for layer in packet.layers:
                if hasattr(layer, 'get_raw_packet'):
                    raw_data = layer.get_raw_packet()
                    if raw_data:
                        image_data.extend(raw_data)

    # Convert the collected byte data into an image
    if image_data:
        image_data = np.array(image_data)
        img_size = int(np.ceil(len(image_data)**0.5))
        image_data = np.pad(image_data, (0, img_size**2 - len(image_data)), 'constant')
        image_data = image_data.reshape((img_size, img_size))
        image = Image.fromarray(image_data)
        image.save(image_file)
        print(f"Image saved as {image_file}")
    else:
        print("No data available to create an image.")

if __name__ == "__main__":
    pcap_to_image('captured.pcap')
