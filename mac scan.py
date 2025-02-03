import scapy.all as scapy
import time
import os

def get_mac(ip):
    """Gets the MAC address of a given IP address using ARP."""
    try:
        arp_request_frame = scapy.ARP(pdst=ip)
        broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
        broadcast_arp_request_frame = broadcast_frame / arp_request_frame

        answered_list = scapy.srp(broadcast_arp_request_frame, timeout=1, verbose=False)[0]  # Send and receive
        
        if answered_list:
            return answered_list[0][1].hwsrc  # Extract MAC address
        else:
            return None  # Or "Unknown"

    except Exception as e:
        print(f"Error getting MAC for {ip}: {e}")
        return None

def scan_network(ip_range):
    """Scans the network for devices and their MAC addresses."""
    try:
        print(f"Scanning network: {ip_range}")
        clients_list = []

        for ip in scapy.arping(ip_range, verbose=False)[1]:  # Use arping for faster scanning
          mac = get_mac(ip)

          if mac:
              clients_list.append({"ip": ip, "mac": mac})
              print(f"IP: {ip} | MAC: {mac}")

        return clients_list
        

    except Exception as e:
        print(f"Network scan error: {e}")
        return None

def listen_for_new_devices(ip_range, existing_macs):
  """Listens for new devices joining the network by monitoring ARP traffic."""
  try:
    print("Listening for new devices...")

    def packet_callback(packet):
      if scapy.ARP in packet and packet[scapy.ARP].op == 1:  # Check if it's an ARP request
        ip = packet[scapy.ARP].psrc
        mac = packet[scapy.Ether].src

        if mac not in existing_macs:
          print(f"New device detected: IP: {ip}, MAC: {mac}")
          existing_macs.add(mac) # Add the new mac address to the existing macs
          with open("new_devices.txt", "a") as f:
            f.write(f"New device detected: IP: {ip}, MAC: {mac}\n")
    
    scapy.sniff(filter="arp", prn=packet_callback, store=0)  # Sniff ARP packets

  except Exception as e:
    print(f"Error listening for new devices: {e}")

if __name__ == "__main__":
  ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")

  # Initial Scan
  clients = scan_network(ip_range)
  if clients:
    existing_macs = {client["mac"] for client in clients} # creates a set of the existing mac addresses

    # Start listening in a separate process or thread (optional but recommended)
    # For simplicity, we'll listen in the main thread in this example.
    listen_for_new_devices(ip_range, existing_macs)
  else:
      print("No devices found during initial scan.")

    