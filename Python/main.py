import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from tensorflow.keras.models import load_model
import threading
import joblib
import pandas as pd
import sys

# Load the preprocessor and models
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
preprocessor_path = './Python/Models/preprocessor.joblib'
preprocessor = joblib.load(preprocessor_path)

iso_forest_path = './Python/Models/isolation_forest_model.joblib'
deep_model_path = './Python/Models/deep_learning_model.h5'

iso_forest = joblib.load(iso_forest_path)
deep_model = load_model(deep_model_path)


def preprocess_packet(packet):
    srcip, dstip = "0.0.0.0", "0.0.0.0"  # Default IPs
    sport, dport, proto = 0, 0, 0  # Default values
    
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

    # data
    features_df = pd.DataFrame([{
        'srcip': str(srcip), 'sport': int(sport), 'dstip': str(dstip), 
        'dsport': int(dport), 'proto': str(proto)
    }])
    
    # Apply the preprocessor to the DataFrame
    processed_features = preprocessor.transform(features_df)
    
    return processed_features
file_lock = threading.Lock()
def analyze_packet(packet):
    processed_features = preprocess_packet(packet)
    is_outlier = iso_forest.predict(processed_features)
    prediction = deep_model.predict(processed_features)

    # Extract packet details
    src_ip, dst_ip, src_port, dst_port, protocol = packet_features(packet)
    
    # Convert deep models prediction to a clear confidence score
    prediction_label = 'Malicious' if prediction[0][0] > 0.4 else 'Benign'
    confidence = float(prediction[0][0])

    # Construct packet details string
    packet_details = f"Packet: SRC {src_ip}:{src_port} -> DST {dst_ip}:{dst_port} on PROTO {protocol}\n"
    packet_details += f"Isolation Forest Outlier: {'Yes' if is_outlier == -1 else 'No'}\n"
    packet_details += f"Deep Learning Prediction: {prediction_label} with confidence {confidence:.2f}\n"

  
    with open("packet_analysis_results.txt", "a", encoding="utf-8") as file:
        file.write(packet_details)

    # Print packet details to the console
    print(packet_details, end="", flush=True)  # Ensure flushing to avoid buffering issues

    if is_outlier == -1:  # If the Isolation Forest model considers it an outlier
        prediction = deep_model.predict(processed_features)

        if prediction > 0.1:
            print(f"Malicious packet detected: SRC {src_ip}:{src_port} -> DST {dst_ip}:{dst_port} on PROTO {protocol}")
        else:
            print(f"Benign packet detected: SRC {src_ip}:{src_port} -> DST {dst_ip}:{dst_port} on PROTO {protocol}")
    else:
        print(f"Benign packet detected: SRC {src_ip}:{src_port} -> DST {dst_ip}:{dst_port} on PROTO {protocol}")





# Additional helper function to extract features and return them.
def packet_features(packet):
    src_ip = packet[IP].src if IP in packet else "N/A"
    dst_ip = packet[IP].dst if IP in packet else "N/A"
    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"
    protocol = packet[IP].proto if IP in packet else "N/A"
    return src_ip, dst_ip, src_port, dst_port, protocol



def start_traffic_capture():
    """
    Start capturing live traffic and analyze each packet.
    """
    sniff(iface='\\Device\\NPF_{3FF1C3E0-336E-4B5F-88A9-134EB82FB3AA}', prn=analyze_packet, store=False)


def start_gui():
    """
    Placeholder for starting a GUI if needed.
    """
    print("GUI would start here. Placeholder function.")

if __name__ == "__main__":
    gui_thread = threading.Thread(target=start_gui)
    gui_thread.start()

    traffic_thread = threading.Thread(target=start_traffic_capture)
    traffic_thread.start()

    gui_thread.join()
    traffic_thread.join()
