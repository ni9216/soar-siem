import time
import requests

logs = [
    "scan detected from 192.168.1.50",
    "failed login attempt detected",
    "ransomware file encrypted",
    "malware outbound connection"
]

while True:

    for log in logs:

        requests.post(
            "http://localhost:5000/api/logs",
            json={
                "log": log,
                "source_ip": "192.168.1.100"
            }
        )

        print("Sent:", log)

        time.sleep(5)
