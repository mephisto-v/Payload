from scapy.all import rdpcap

# Load the .ivs file
packets = rdpcap('wep-crackable.ivs')

# Iterate over the packets
for packet in packets:
    print(packet.summary())
