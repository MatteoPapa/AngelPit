import asyncio
import aiohttp
import ssl
import time
from collections import Counter
import sys 

PORT = sys.argv[1] if len(sys.argv) > 1 else 5000
TARGET_URL = f"http://127.0.0.1:{PORT}"
TOTAL_REQUESTS = 5000
DURATION_SECONDS = 60
REQUESTS_PER_SECOND = TOTAL_REQUESTS // DURATION_SECONDS
CACERT_PATH = "../ca-cert.pem"
TIMEOUT_SECONDS = 15

# Track results globally
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

    # Drain new results from the queue
    for _ in range(REQUESTS_PER_SECOND):
        result_type, detail = await results_queue.get()
        if result_type == 'success':
            local_success += 1
        else:
            local_errors[detail] += 1

    # Log for this second
    print(f"[{second_index+1:02d}s] ✅ Success: {local_success}, ❌ Errors: {sum(local_errors.values())}")
    for error_msg, count in local_errors.items():
        print(f"        - {count} × {error_msg}")

async def main():
    ssl_context = ssl.create_default_context(cafile=CACERT_PATH)
    # connector = aiohttp.TCPConnector(ssl=ssl_context)
    connector = aiohttp.TCPConnector()

    total_success = 0
    total_errors = 0

    async with aiohttp.ClientSession(connector=connector) as session:
        for second in range(DURATION_SECONDS):
            start = time.time()
            interval = 1 / REQUESTS_PER_SECOND
            # Fire and await each batch now (for cleaner per-second logging)
            await send_requests_batch(session, interval, second)
            elapsed = time.time() - start
            if elapsed < 1:
                await asyncio.sleep(1 - elapsed)

    print(f"\n📊 Benchmark Complete:")
    print(f"    Total Sent:   {TOTAL_REQUESTS}")
    print(f"    Total Success:✅ {total_success}")
    print(f"    Total Errors: ❌ {TOTAL_REQUESTS - total_success}")

if __name__ == "__main__":
    asyncio.run(main())
