"""
Unit Tests for Assignment 2 — Port Scanner
"""

import unittest

# Importing classes and dictionary from the main assignment file
from assignment2_101584721 import PortScanner, common_ports

class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):
        """Test that PortScanner initializes with correct target and empty results list."""
        scanner = PortScanner("127.0.0.1")
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.scan_results, [])

    def test_get_open_ports_filters_correctly(self):
        """Test that get_open_ports returns only Open ports."""
        scanner = PortScanner("127.0.0.1")
        scanner.scan_results = [
            (22, "Open", "SSH"), 
            (23, "Closed", "Telnet"), 
            (80, "Open", "HTTP")
        ]
        open_ports = scanner.get_open_ports()
        self.assertEqual(len(open_ports), 2)
        self.assertIn((22, "Open", "SSH"), open_ports)
        self.assertIn((80, "Open", "HTTP"), open_ports)

    def test_common_ports_dict(self):
        """Test that common_ports dictionary has correct entries."""
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")

    def test_invalid_target(self):
        """Test that setter rejects empty string target."""
        scanner = PortScanner("127.0.0.1")
        scanner.target = "" # Attempt to set empty string
        # The setter prints an error and ignores the change, so target remains 127.0.0.1
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()