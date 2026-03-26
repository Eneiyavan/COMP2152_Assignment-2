"""
Author: Eneiyavan Sivaganesan
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and Operating System
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their respective service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.target = target # Uses setter for validation

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter provides encapsulation, allowing us to control how the attribute is accessed and modified. 
    # It ensures data validation (like rejecting empty strings) is enforced automatically without breaking existing code that accesses the attribute directly.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, meaning it automatically gains its attributes and methods without needing to rewrite them. 
# For example, it directly reuses the target property getter and setter, ensuring IP validation is handled by the parent class.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        # Check if parent has __del__ before calling to avoid AttributeError in some Python versions
        if hasattr(super(), '__del__'):
            super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without a try-except block, encountering a network error (like an unreachable host or dropped connection) would raise an unhandled socket.error exception. 
        # This would crash the specific thread running the scan and potentially halt the entire program.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
            
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows us to scan multiple ports concurrently, vastly reducing the overall execution time. 
    # If we scanned 1024 ports sequentially without threads, the program would have to wait for each port's timeout individually, which could take over 17 minutes to finish.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            
        for thread in threads:
            thread.start()
            
        for thread in threads:
            thread.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)
        
        scan_date = str(datetime.datetime.now())
        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date) 
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, scan_date))
            
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    try:
        if not os.path.exists("scan_history.db"):
            print("No past scans found.")
            return

        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        
        # Check if table exists before querying
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        if not cursor.fetchone():
            print("No past scans found.")
            conn.close()
            return
            
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
                
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        target_ip = input("Enter target IP (default 127.0.0.1): ").strip()
        if not target_ip:
            target_ip = "127.0.0.1"
            
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))
        
        if not (1 <= start_port <= 1024) or not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target_ip)
            print(f"\nScanning {scanner.target} from port {start_port} to {end_port}...\n")
            
            scanner.scan_range(start_port, end_port)
            open_ports = scanner.get_open_ports()
            
            print(f"--- Scan Results for {scanner.target} ---")
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}\n")
            
            if open_ports:
                save_results(scanner.target, open_ports)
                
            show_history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if show_history == 'yes':
                print("\n--- Past Scan History ---")
                load_past_scans()
                print("-------------------------\n")
                
    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal
# I would add a "Port Risk Classifier" that categorizes open ports into Risk Levels (e.g., High, Medium, Low) based on known vulnerabilities. 
# This would use a nested if-statement inside the scan output loop to check if an open port belongs to a high-risk list (like 21, 22, 23) and append a specific security warning flag to the print output.
# Diagram: See diagram_101584721.png in the repository root