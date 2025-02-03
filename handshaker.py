import subprocess
import os
import time
from scapy.all import *

def capture_handshake(interface, bssid, filename="handshake.pcap"):
    """Captures a WiFi handshake and saves it to a file."""

    print(f"Capturing handshake for BSSID: {bssid} on interface: {interface}")

    # Construct the tshark command (using tshark for better control)
    tshark_command = [
        "tshark",
        "-i", interface,
        "-w", filename,  # Write to file
        "-b", "capture,bpf", f"wlan addr1 {bssid} or wlan addr2 {bssid}", # Capture only traffic to/from target AP
        "-c", "500"  # Capture a reasonable number of packets (adjust as needed)
    ]

    try:
        print("Starting capture...")
        tshark_process = subprocess.Popen(tshark_command, stderr=subprocess.PIPE) # Capture stderr for debugging

        # Give some time for the capture to start (important!)
        time.sleep(5) # Adjust if needed

        print("Press Ctrl+C to stop capture.")
        tshark_process.wait() # Wait for the process to finish or be interrupted
        print("Capture finished.")


        # Check for errors during capture
        _, stderr = tshark_process.communicate()  # Get stderr output
        if stderr:
            print(f"tshark error: {stderr.decode()}")  # Print any errors
            return None # Indicate failure

        return filename  # Return the filename of the captured handshake

    except KeyboardInterrupt:
        print("Capture stopped by user.")
        tshark_process.terminate() # Ensure tshark is terminated
        return filename  # Return filename even if interrupted

    except FileNotFoundError:
        print("Error: tshark not found. Make sure it's installed.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def decode_handshake(pcap_file):
    """Decodes a captured handshake (EAPOL) from a pcap file."""
    try:
        packets = rdpcap(pcap_file) # Scapy to read the pcap
        eapol_packets = [pkt for pkt in packets if EAPOL in pkt]  # Filter for EAPOL packets

        if not eapol_packets:
            print("No EAPOL packets found in the capture file. Handshake not captured or corrupted.")
            return None

        decoded_handshake_text = ""
        for packet in eapol_packets:
            decoded_handshake_text += str(packet.show(dump=True)) + "\n" # show(dump=True) gives detailed output

        return decoded_handshake_text

    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
        return None
    except Exception as e:
         print(f"An error occurred during decoding: {e}")
         return None



if __name__ == "__main__":
    interface = input("Enter the interface to use (e.g., wlan0): ")  # Get the interface
    bssid = input("Enter the BSSID of the target AP (e.g., AA:BB:CC:DD:EE:FF): ")  # Get the BSSID

    pcap_filename = "handshake.pcap"  # Default filename
    captured_file = capture_handshake(interface, bssid, pcap_filename)

    if captured_file:
        decoded_text = decode_handshake(captured_file)

        if decoded_text:
            output_filename = "handshake_decoded.txt"
            with open(output_filename, "w") as f:
                f.write(decoded_text)
            print(f"Handshake decoded and saved to {output_filename}")
        else:
            print("Handshake decoding failed.")

    else:
        print("Handshake capture failed.")

      