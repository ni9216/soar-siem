import os
import time
import requests

API_URL = os.getenv('API_URL', 'http://localhost:5000')

logs = [
    "scan detected from 192.168.1.50",
    "failed login attempt detected",
    "ransomware file encrypted",
    "malware outbound connection"
]

while True:
    for log in logs:
        try:
            requests.post(
                f"{API_URL}/api/logs",
                json={"log": log, "source_ip": "192.168.1.100"},
                timeout=5
            )
            print("Sent:", log)
        except Exception as e:
            print(f"Failed to send log: {e}")
        time.sleep(5)
