import requests
import sys

# Path to your trusted CA certificate
CA_CERT = "../ca-cert.pem"

# Create a persistent session
session = requests.Session()
session.verify = CA_CERT  # Trust only this CA
session.headers.update({"Content-Type": "application/json", "User-Agent": "requests"})

url = "http://127.0.0.1:5000"

data = sys.argv[1] if len(sys.argv) > 1 else "banana"
print(f"🔹 Sending POST request with data: {data}")

# 🔹 Step 1: Trigger request
trigger_data = {"fruit": data}
trigger_response = session.post(url, json=trigger_data)
print("🔶 Trigger Request")
print(f"Status: {trigger_response.status_code}")
print("Response:", trigger_response.text)
print()

# 🔹 Step 2: Follow-up request
normal_data = {"note": "nothing special"}
normal_response = session.post(url, json=normal_data)
print("🔹 Follow-up Request")
print(f"Status: {normal_response.status_code}")
print("Response:", normal_response.text)
print()

# 🔹 Step 3: GET request
get_response = session.get(url)
print("🔹 GET Request")
print(f"Status: {get_response.status_code}")
print("Response:", get_response.text)
