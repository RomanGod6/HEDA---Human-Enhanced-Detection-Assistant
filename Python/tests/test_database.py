import unittest
import sqlite3
from main import init_db, update_db_schema, log_packet

class TestDatabase(unittest.TestCase):
    def setUp(self):
        # Setup test database connection
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        init_db()
        update_db_schema()
    
    def tearDown(self):
        # Close the database connection after each test
        self.conn.close()

    def test_log_packet(self):
        log_id = log_packet('192.168.1.1', '192.168.1.2', 12345, 80, 'TCP', 100, 'S', 'payload', 'packet_details', True, 0.95, 'prediction', 'attack_type', 0.1, 1.0, 50, 0.5, 50, 'state', 128, 128, 'http')
        self.assertIsNotNone(log_id)
        self.cursor.execute('SELECT * FROM firewall_logs WHERE id = ?', (log_id,))
        row = self.cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], '192.168.1.1')

if __name__ == '__main__':
    unittest.main()
