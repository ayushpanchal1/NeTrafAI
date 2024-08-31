import os
from capture_traffic import capture_traffic
from pcap_to_image import pcap_to_image
from predict_malware import load_and_predict
from display_image import display_image

def main():
    # Step 1: Capture network traffic
    # capture_traffic()

    # Step 2: Convert PCAP to image
    pcap_to_image('captured.pcap')

    # Step 3: Run image through CNN classifier
    # prediction = load_and_predict('pcap_image.png')

    # # Step 4: Display image and notify user
    # display_image('pcap_image.png')
    # if prediction > 0.5:
    #     print("Malware detected!")
    # else:
    #     print("No malware detected.")

if __name__ == "__main__":
    main()
