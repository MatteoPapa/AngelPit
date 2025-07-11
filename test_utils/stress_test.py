import asyncio
import aiohttp
import ssl
import time
from collections import Counter
import sys

# ==== Configuration ====
REQUESTS_PER_SECOND = 40  # 🔁 Fixed frequency
DURATION_MINUTES = 20
PORT = sys.argv[1] if len(sys.argv) > 1 else 5000  # Optional port as second arg

# ==== Derived Config ====
DURATION_SECONDS = DURATION_MINUTES * 60
TOTAL_REQUESTS = REQUESTS_PER_SECOND * DURATION_SECONDS
TARGET_URL = f"https://localhost:{PORT}"  # Localhost for testing
# TARGET_URL = f"http://37.27.33.26:{PORT}"
CACERT_PATH = "../ca-cert.pem"
TIMEOUT_SECONDS = 15

# ==== Globals ====
results_queue = asyncio.Queue()

async def fetch(session, url):
    try:
        timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        async with session.get(url, timeout=timeout) as response:
            await results_queue.put(('success', response.status))
    except Exception as e:
        await results_queue.put(('error', str(e)))

async def send_requests_batch(session, interval, second_index):
    local_success = 0
    local_errors = Counter()
    tasks = []

    for _ in range(REQUESTS_PER_SECOND):
        task = asyncio.create_task(fetch(session, TARGET_URL))
        tasks.append(task)
        await asyncio.sleep(interval)

    await asyncio.gather(*tasks)

    for _ in range(REQUESTS_PER_SECOND):
        result_type, detail = await results_queue.get()
        if result_type == 'success':
            local_success += 1
        else:
            local_errors[detail] += 1

    print(f"[{second_index+1:02d}s] ✅ Success: {local_success}, ❌ Errors: {sum(local_errors.values())}")
    for error_msg, count in local_errors.items():
        print(f"        - {count} × {error_msg}")

    return local_success, sum(local_errors.values())

async def main():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)

    # connector = aiohttp.TCPConnector()

    total_success = 0
    total_errors = 0

    async with aiohttp.ClientSession(connector=connector) as session:
        running_batches = []

        for second in range(DURATION_SECONDS):
            interval = 1 / REQUESTS_PER_SECOND
            task = asyncio.create_task(send_requests_batch(session, interval, second))
            running_batches.append(task)
            await asyncio.sleep(1)

        results = await asyncio.gather(*running_batches)

        for successes, errors in results:
            total_success += successes
            total_errors += errors

    print(f"\n📊 Benchmark Complete:")
    print(f"    Duration:     {DURATION_MINUTES} minute(s)")
    print(f"    Total Sent:   {TOTAL_REQUESTS}")
    print(f"    Total Success:✅ {total_success}")
    print(f"    Total Errors: ❌ {total_errors}")

if __name__ == "__main__":
    asyncio.run(main())
