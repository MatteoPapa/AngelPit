import asyncio
import aiohttp
import ssl
import random
import string
from aiohttp import TCPConnector, ClientTimeout
from asyncio import TimeoutError
from collections import Counter
import sys
import time

# ======== CONFIGURATION ========
CA_CERT_PATH = "./ca-cert.pem"
PORT = sys.argv[1] if len(sys.argv) > 1 else "5000"
URL = f"https://127.0.0.1:{PORT}"

NUM_REQUESTS = 20000           # Total number of requests to send
CONCURRENCY_LIMIT = 1000       # Max number of concurrent connections
BATCH_SIZE = 1000              # Requests per wave
DELAY_BETWEEN_BATCHES = 1      # Seconds to pause between batches
REQUEST_TIMEOUT = 10           # Per-request timeout in seconds

# ======== SSL SETUP ========
ssl_ctx = ssl.create_default_context(cafile=CA_CERT_PATH)
ssl_ctx.check_hostname = False

# ======== STATS TRACKING ========
failures = Counter()
start_time = time.time()

# ======== PAYLOAD GENERATION ========
def random_payload():
    text = ''.join(random.choices(string.ascii_lowercase, k=8))
    return {"fruit": text if random.random() > 0.2 else "banana"}

# ======== REQUEST FUNCTION ========
async def send_request(session, i):
    try:
        data = random_payload()
        async with session.post(URL, json=data) as resp:
            text = await resp.text()
            print(f"[{i:05}] {resp.status} - {data['fruit']}: {text[:60]}")
    except TimeoutError:
        failures["timeout"] += 1
        print(f"[{i:05}] Timeout")
    except Exception as e:
        failures["other"] += 1
        print(f"[{i:05}] Failed: {e}")

# ======== MAIN LOGIC ========
async def main():
    timeout = ClientTimeout(total=REQUEST_TIMEOUT)
    connector = TCPConnector(ssl=ssl_ctx, limit=CONCURRENCY_LIMIT)
    headers = {
        "User-Agent": "CHECKER",
        "Content-Type": "application/json"
    }

    async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout) as session:
        for i in range(0, NUM_REQUESTS, BATCH_SIZE):
            batch = [send_request(session, i + j) for j in range(min(BATCH_SIZE, NUM_REQUESTS - i))]
            await asyncio.gather(*batch)
            await asyncio.sleep(DELAY_BETWEEN_BATCHES)

    elapsed = time.time() - start_time
    print("\n✅ Load test completed.")
    print(f"📈 Total requests: {NUM_REQUESTS}")
    print(f"✅ Successes: {NUM_REQUESTS - failures['timeout'] - failures['other']}")
    print(f"❌ Timeouts: {failures['timeout']}")
    print(f"⚠️  Other failures: {failures['other']}")
    print(f"⏱ Duration: {elapsed:.2f} seconds")
    print(f"🚀 Requests/sec: {NUM_REQUESTS / elapsed:.2f}")

# ======== ENTRY POINT ========
if __name__ == "__main__":
    asyncio.run(main())
