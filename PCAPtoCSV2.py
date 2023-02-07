import csv
import os
from scapy.all import *

def pcap_to_csv(pcap_file, csv_file):
    packets = rdpcap(pcap_file)
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "source", "destination", "protocol", "length"])
        for packet in packets:
            try:
                writer.writerow([packet.time, packet[IP].src, packet[IP].dst, packet[IP].proto, len(packet)])
            except:
                pass

directory = input("Enter the name of the directory containing the PCAP files: ")
pcap_files = [f for f in os.listdir(directory) if f.endswith(".pcap")]

for pcap_file in pcap_files:
    csv_file = pcap_file.replace(".pcap", ".csv")
    pcap_to_csv(os.path.join(directory, pcap_file), os.path.join(directory, csv_file))

print("Conversion complete!")
