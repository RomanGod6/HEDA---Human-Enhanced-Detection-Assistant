import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP, raw
from scapy.arch.windows import get_windows_if_list
from tensorflow.keras.models import load_model
import threading
import joblib
import pandas as pd
import sys
import sqlite3
import datetime
from collections import defaultdict
import signal
import subprocess
from win10toast import ToastNotifier

toaster = ToastNotifier()
# Load the preprocessor and models
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
preprocessor_path = './Python/Models/preprocessor.joblib'
preprocessor = joblib.load(preprocessor_path)

iso_forest_path = './Python/Models/isolation_forest_model.joblib'
deep_model_path = './Python/Models/deep_learning_model.h5'

iso_forest = joblib.load(iso_forest_path)
deep_model = load_model(deep_model_path)

# Initialize previous packet time and length for new features
previous_pkt_time = 0
previous_pkt_length = 0

# Initialize database
def init_db():
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    # Create tables if they don't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS firewall_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            malicious BOOLEAN,
            confidence REAL,
            model_output TEXT,
            length INTEGER,
            flags TEXT,
            payload TEXT,
            packet_details TEXT,
            inter_arrival_time REAL,
            byte_ratio REAL,
            sbytes INTEGER,
            dur REAL,
            dbytes INTEGER,
            state TEXT,
            sttl INTEGER,
            dttl INTEGER,
            service TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            notified BOOLEAN DEFAULT 0,
            notification_timestamp DATETIME,
            acknowledged BOOLEAN DEFAULT 0,
            FOREIGN KEY (log_id) REFERENCES firewall_logs (id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS auto_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            response TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (log_id) REFERENCES firewall_logs (id)
        )
    ''')
    conn.commit()
    conn.close()

def fetch_latest_settings():
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    c.execute('SELECT automaticThreatResponse, selectedOption FROM securityactions WHERE isActive = 1 ORDER BY updateTime DESC LIMIT 1')
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'automaticThreatResponse': row[0],
            'selectedOption': row[1]
        }
    return None

def log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output, inter_arrival_time, byte_ratio, sbytes, dur, dbytes, state, sttl, dttl, service):
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO firewall_logs (src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output, inter_arrival_time, byte_ratio, sbytes, dur, dbytes, state, sttl, dttl, service)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output, inter_arrival_time, byte_ratio, sbytes, dur, dbytes, state, sttl, dttl, service))
    conn.commit()
    log_id = c.lastrowid
    conn.close()
    return log_id

def log_notification(log_id):
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO notifications (log_id, notified, notification_timestamp, acknowledged)
        VALUES (?, ?, ?, ?)
    ''', (log_id, 1, datetime.datetime.now().isoformat(), 0))
    conn.commit()
    conn.close()

def log_auto_response(log_id, response):
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO auto_responses (log_id, response, timestamp)
        VALUES (?, ?, ?)
    ''', (log_id, response, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_whitelist():
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    c.execute('SELECT ip_address FROM whitelist')
    rows = c.fetchall()
    conn.close()
    return [row[0] for row in rows]

def firewall_rule_exists(ip_address):
    check_command = f"Get-NetFirewallRule | Get-NetFirewallAddressFilter | Where-Object {{ $_.RemoteAddress -eq '{ip_address}' }}"
    result = subprocess.run(["powershell", "-Command", check_command], capture_output=True, text=True)
    return bool(result.stdout.strip())

def block_ip(ip_address):
    try:
        if firewall_rule_exists(ip_address):
            print(f"Firewall rule already exists for IP: {ip_address}")
            toaster.show_toast("Firewall Alert", f"Firewall rule already exists for IP: {ip_address}", duration=10)
            return

        # Block outbound traffic
        command_outbound = f"New-NetFirewallRule -DisplayName 'Block {ip_address} Outbound' -Direction Outbound -RemoteAddress {ip_address} -Action Block"
        subprocess.run(["powershell", "-Command", command_outbound], check=True)
        
        # Block inbound traffic
        command_inbound = f"New-NetFirewallRule -DisplayName 'Block {ip_address} Inbound' -Direction Inbound -RemoteAddress {ip_address} -Action Block"
        subprocess.run(["powershell", "-Command", command_inbound], check=True)
        
        print(f"Successfully blocked IP: {ip_address}")
        toaster.show_toast("Firewall Alert", f"Successfully blocked IP: {ip_address}", duration=10)
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e}")
        toaster.show_toast("Firewall Alert", f"Error blocking IP {ip_address}: {e}", duration=10)

# Dictionary to store flow state
flow_state = defaultdict(lambda: {
    'start_time': None, 'src_bytes': 0, 'dst_bytes': 0, 'packet_count': 0
})

def preprocess_packet(packet):
    global previous_pkt_time, previous_pkt_length

    srcip, dstip = "0.0.0.0", "0.0.0.0"
    sport, dport, proto = 0, 0, 0
    length, flags, payload, pkt_time = 0, "", "", 0
    sttl, dttl, service = 0, 0, "N/A"  # Initialize new features
    
    if IP in packet:
        srcip = packet[IP].src
        dstip = packet[IP].dst
        proto = packet[IP].proto
        pkt_time = packet.time
        sttl = packet[IP].ttl  # Source TTL
        
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet.sprintf('%TCP.flags%')
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif ICMP in packet:
        sport, dport = 0, 0

    length = len(packet)
    payload = raw(packet[IP].payload).hex() if IP in packet else "N/A"

    # Determine service based on destination port
    if dport in [80, 443]:
        service = "http"
    elif dport == 53:
        service = "dns"
    elif dport == 21:
        service = "ftp"
    
    # Log additional packet details for inspection
    print(f"Packet Info: SRC {srcip}:{sport} -> DST {dstip}:{dport} PROTO {proto} LENGTH {length}")
    print(f"Payload: {payload[:50]}...")  # Log a snippet of the payload for a quick check

    # Update flow state
    flow_key = (srcip, sport, dstip, dport, proto)
    flow = flow_state[flow_key]
    
    if flow['start_time'] is None:
        flow['start_time'] = pkt_time
        
    dur = pkt_time - flow['start_time']
    
    if IP in packet:
        if packet[IP].src == srcip:
            sbytes = flow['src_bytes'] + length
            flow['src_bytes'] += length
            dbytes = flow['dst_bytes']
        else:
            dbytes = flow['dst_bytes'] + length
            flow['dst_bytes'] += length
            sbytes = flow['src_bytes']
    else:
        sbytes = 0
        dbytes = 0
    
    flow['packet_count'] += 1

    inter_arrival_time = pkt_time - previous_pkt_time
    inter_arrival_time = max(inter_arrival_time, 0)  # Ensure non-negative value
    byte_ratio = length / (previous_pkt_length if previous_pkt_length != 0 else 1)
    
    # Update previous packet time and length
    previous_pkt_time = pkt_time
    previous_pkt_length = length

    state = flags  # Assuming state refers to TCP flags, update as needed

    features_df = pd.DataFrame([{
        'srcip': str(srcip), 'sport': int(sport), 'dstip': str(dstip), 
        'dsport': int(dport), 'proto': str(proto), 'length': length, 
        'flags': flags, 'payload': payload, 'pkt_time': pkt_time,
        'inter_arrival_time': inter_arrival_time, 'byte_ratio': byte_ratio,
        'dur': dur, 'sbytes': sbytes, 'dbytes': dbytes, 'state': state, 'sttl': sttl, 'dttl': dttl, 'service': service
    }])

    # Log the computed values for inspection
    print(f"Computed values: sbytes={sbytes}, dbytes={dbytes}, state={state}, sttl={sttl}, dttl={dttl}, service={service}")

    processed_features = preprocessor.transform(features_df)
    return processed_features, inter_arrival_time, byte_ratio, dur, sbytes, dbytes, state, sttl, dttl, service

def analyze_packet(packet):
    try:
        # Fetch the latest settings
        settings = fetch_latest_settings()
        if not settings:
            print("No settings found in the database. Skipping packet analysis.")
            return

        processed_features, inter_arrival_time, byte_ratio, dur, sbytes, dbytes, state, sttl, dttl, service = preprocess_packet(packet)
        is_outlier = iso_forest.predict(processed_features)
        prediction = deep_model.predict(processed_features)
        src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload = packet_features(packet)
        packet_details = packet.show(dump=True)
        
        prediction_label = 'Malicious' if prediction[0][0] > 0.7 else 'Benign'
        confidence = float(prediction[0][0])
        malicious = prediction_label == 'Malicious'

        # Retrieve whitelist from database
        whitelist = get_whitelist()

        # Check if the source or destination IP is in the whitelist
        if src_ip in whitelist or dst_ip in whitelist:
            print(f"Packet from {src_ip} to {dst_ip} is whitelisted. Skipping analysis.")
            return

        # Log to database
        log_id = log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, str(prediction), inter_arrival_time, byte_ratio, sbytes, dur, dbytes, state, sttl, dttl, service)

        # Log notification if packet is malicious
        if malicious:
            log_notification(log_id)

        # Auto response actions based on selected option
        response = ""
        if settings['selectedOption'] == 'option1':
            # Block all malicious packets and stop all traffic except whitelisted
            if malicious:
                response = f"Blocking malicious packet from {src_ip} to {dst_ip} and stopping all traffic except whitelisted IPs."
                print(response)
                block_ip(src_ip)
        elif settings['selectedOption'] == 'option2':
            # Block all malicious packets and allow all other non-malicious traffic
            if malicious:
                response = f"Blocking malicious packet from {src_ip} to {dst_ip}."
                print(response)
                block_ip(src_ip)
        elif settings['selectedOption'] == 'option3':
            # Notify only for malicious packets
            if malicious:
                response = f"Notifying about malicious packet from {src_ip} to {dst_ip}."
                print(response)
                # Implement notification logic here
        
        if response:
            log_auto_response(log_id, response)

        packet_details_output = f"Packet: SRC {src_ip}:{src_port} -> DST {dst_ip}:{dst_port} on PROTO {protocol}\n"
        packet_details_output += f"Length: {length} Flags: {flags} Payload: {payload}\n"
        packet_details_output += f"Isolation Forest Outlier: {'Yes' if is_outlier == -1 else 'No'}\n"
        packet_details_output += f"Deep Learning Prediction: {prediction_label} with confidence {confidence:.2f}\n"
        packet_details_output += f"Packet Details: {packet_details}\n"
        packet_details_output += f"Inter Arrival Time: {inter_arrival_time}\n"
        packet_details_output += f"Byte Ratio: {byte_ratio}\n"
        packet_details_output += f"Duration: {dur}\n"
        packet_details_output += f"SBytes: {sbytes}\n"
        packet_details_output += f"DBytes: {dbytes}\n"
        packet_details_output += f"State: {state}\n"
        packet_details_output += f"STTL: {sttl}\n"
        packet_details_output += f"DTTL: {dttl}\n"
        packet_details_output += f"Service: {service}\n"
        print(packet_details_output, end="", flush=True)
    except Exception as e:
        print(f"Error analyzing packet: {e}")

def packet_features(packet):
    src_ip = packet[IP].src if IP in packet else "N/A"
    dst_ip = packet[IP].dst if IP in packet else "N/A"
    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"
    protocol = packet[IP].proto if IP in packet else "N/A"
    length = len(packet)
    flags = packet.sprintf('%TCP.flags%') if TCP in packet else "N/A"
    payload = raw(packet[IP].payload).hex() if IP in packet else "N/A"
    return src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload

def start_traffic_capture_on_interface(interface):
    try:
        print(f"Starting traffic capture on interface: {interface['name']}")
        sniff(iface=interface['name'], prn=analyze_packet, store=False)
    except OSError as e:
        print(f"Could not open interface {interface['name']}: {e}")

def start_traffic_capture():
    interfaces = get_windows_if_list()
    valid_interfaces = [iface for iface in interfaces if 'Npcap' in iface['description'] or 'Wi-Fi' in iface['description'] or 'Ethernet' in iface['description']]
    print(f"Available interfaces: {valid_interfaces}")
    threads = []
    for interface in valid_interfaces:
        if 'name' in interface:
            t = threading.Thread(target=start_traffic_capture_on_interface, args=(interface,))
            t.start()
            threads.append(t)
    
    for t in threads:
        t.join()

def start_gui():
    print("GUI would start here. Placeholder function.")

def signal_handler(sig, frame):
    print('You pressed Ctrl+C! Exiting gracefully...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    print(get_windows_if_list())  # List available interfaces for verification
    init_db()  # Initialize the database at start
    gui_thread = threading.Thread(target=start_gui)
    gui_thread.start()
    traffic_thread = threading.Thread(target=start_traffic_capture)
    traffic_thread.start()
    gui_thread.join()
    traffic_thread.join()
