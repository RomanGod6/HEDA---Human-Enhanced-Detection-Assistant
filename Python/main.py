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

# Load the preprocessor and models
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
preprocessor_path = './Python/Models/preprocessor.joblib'
preprocessor = joblib.load(preprocessor_path)

iso_forest_path = './Python/Models/isolation_forest_model.joblib'
deep_model_path = './Python/Models/deep_learning_model.h5'

iso_forest = joblib.load(iso_forest_path)
deep_model = load_model(deep_model_path)

# Initialize database
def init_db():
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    # Create table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
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
            packet_details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output):
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output))
    conn.commit()
    conn.close()

def preprocess_packet(packet):
    srcip, dstip = "0.0.0.0", "0.0.0.0"
    sport, dport, proto = 0, 0, 0
    
    if IP in packet:
        srcip = packet[IP].src
        dstip = packet[IP].dst
        proto = packet[IP].proto
        
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif ICMP in packet:
        sport = 0
        dport = 0

    features_df = pd.DataFrame([{
        'srcip': str(srcip), 'sport': int(sport), 'dstip': str(dstip), 
        'dsport': int(dport), 'proto': str(proto)
    }])
    
    processed_features = preprocessor.transform(features_df)
    return processed_features

def hex_to_readable_string(hex_str):
    try:
        bytes_object = bytes.fromhex(hex_str)
        readable_string = ''
        for byte in bytes_object:
            if 32 <= byte < 127:  # Printable ASCII range
                readable_string += chr(byte)
            else:
                readable_string += f'\\x{byte:02x}'
        return readable_string
    except Exception as e:
        return f"Error converting hex to string: {e}"

def analyze_packet(packet):
    processed_features = preprocess_packet(packet)
    is_outlier = iso_forest.predict(processed_features)
    prediction = deep_model.predict(processed_features)
    src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload = packet_features(packet)
    packet_details = packet.show(dump=True)
    
    prediction_label = 'Malicious' if prediction[0][0] > 0.8 else 'Benign'
    confidence = float(prediction[0][0])
    malicious = prediction_label == 'Malicious'
    
    # Log to database
    log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, str(prediction))

    packet_details_output = f"Packet: SRC {src_ip}:{src_port} -> DST {dst_ip}:{dst_port} on PROTO {protocol}\n"
    packet_details_output += f"Length: {length} Flags: {flags} Payload: {payload}\n"
    packet_details_output += f"Isolation Forest Outlier: {'Yes' if is_outlier == -1 else 'No'}\n"
    packet_details_output += f"Deep Learning Prediction: {prediction_label} with confidence {confidence:.2f}\n"
    packet_details_output += f"Packet Details: {packet_details}\n"
    print(packet_details_output, end="", flush=True)

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

if __name__ == "__main__":
    print(get_windows_if_list())  # List available interfaces for verification
    init_db()  # Initialize the database at start
    gui_thread = threading.Thread(target=start_gui)
    gui_thread.start()
    traffic_thread = threading.Thread(target=start_traffic_capture)
    traffic_thread.start()
    gui_thread.join()
    traffic_thread.join()
