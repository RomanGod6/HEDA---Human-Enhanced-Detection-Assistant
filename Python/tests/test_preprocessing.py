import unittest
from unittest.mock import MagicMock
from scapy.all import IP, TCP, UDP, ICMP
from main import preprocess_packet

class TestPreprocessing(unittest.TestCase):
    def test_preprocess_packet(self):
        # Mock packet data
        packet = MagicMock()
        packet.time = 1609459200 
        
        # Set up packet attributes
        packet[IP].src = '192.168.1.1'
        packet[IP].dst = '192.168.1.2'
        packet[IP].proto = 6  # TCP
        packet[TCP].sport = 12345
        packet[TCP].dport = 80
        packet.sprintf.return_value = 'S'
        packet[IP].payload = MagicMock()
        packet[IP].payload.hex.return_value = 'abcd1234'
        
        # Call the preprocessing function
        processed_features, inter_arrival_time, byte_ratio, dur, sbytes, dbytes, state, sttl, dttl, service = preprocess_packet(packet)
        
        # Verify the processed output
        self.assertEqual(processed_features.shape[1], 18)  # Assuming 18 features
        self.assertEqual(inter_arrival_time, 0)  # Assuming no previous packet
        self.assertEqual(service, 'http')

if __name__ == '__main__':
    unittest.main()
