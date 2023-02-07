import csv
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

pcap_files = [
    "file1.pcap",
    "file2.pcap",
    # Add additional pcap files as needed
]

for pcap_file in pcap_files:
    csv_file = pcap_file.replace(".pcap", ".csv")
    pcap_to_csv(pcap_file, csv_file)
