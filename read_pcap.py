from scapy import rdpcap
import re

#variable which holdes the path for the file
file_name = input("Filepath")

# Loads the pcap file into the program
pcap_file = rdpcap(file_name)

txt_answers = [
    p for p in packets
    if p.haslayer(DNS) and p[DNS].qr == 1 and p[DNS].an.type == 16
]

print(f"Found {len(txt_anwers)} TXT-anwers.")



#contains the raw hex bytestring 
for packet in txt_answers:
    # henter in rdata (i scapy er dette en tuple)
    raw_data = packet[0][DNS].an.rdata
    #Henter ut bytestrengen og konverterer til en python sterng 
    hex_string = raw_data[0].decode('UTF-8')

    #dekoder hex-data til lesbar tekst
    try:
        decoded_hex = bytes.fromhex(hex_string).decode('UTF-8')
        print(decoded_hex)
    except ValueError:
        print("Could not decode packet")
    
    




