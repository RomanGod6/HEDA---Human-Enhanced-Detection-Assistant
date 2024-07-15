import unittest
from unittest.mock import patch
from main import block_ip, firewall_rule_exists

class TestNetworkFunctions(unittest.TestCase):
    @patch('main.subprocess.run')
    def test_firewall_rule_exists(self, mock_run):
        mock_run.return_value.stdout = "Some output indicating rule exists"
        self.assertTrue(firewall_rule_exists('192.168.1.1'))
        mock_run.return_value.stdout = ""
        self.assertFalse(firewall_rule_exists('192.168.1.1'))

    @patch('main.subprocess.run')
    def test_block_ip(self, mock_run):
        block_ip('192.168.1.1')
        self.assertEqual(mock_run.call_count, 2)

if __name__ == '__main__':
    unittest.main()
