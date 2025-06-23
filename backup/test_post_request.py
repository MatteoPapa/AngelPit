# post_request.py

import requests
import urllib3
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create a persistent session
session = requests.Session()
session.verify = False  # Accept self-signed cert
session.headers.update({"Content-Type": "application/json"})

url = "https://127.0.0.1:5000"

data = sys.argv[1] if len(sys.argv) > 1 else "banana"
print(f"🔹 Sending POST request with data: {data}")
# 🔹 Step 1: Send a POST that triggers the keyword
trigger_data = {"fruit": data}
trigger_response = session.post(url, json=trigger_data)
print("🔶 Trigger Request")
print(f"Status: {trigger_response.status_code}")
print("Response:", trigger_response.text)
print()

# 🔹 Step 2: Send a second request that does NOT contain the keyword
normal_data = {"note": "nothing special"}
normal_response = session.post(url, json=normal_data)
print("🔹 Follow-up Request")
print(f"Status: {normal_response.status_code}")
print("Response:", normal_response.text)
print()

# 🔹 Step 3: GET request in same session
get_response = session.get(url)
print("🔹 GET Request")
print(f"Status: {get_response.status_code}")
print("Response:", get_response.text)
