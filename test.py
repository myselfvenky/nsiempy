import asyncio
import aiohttp
import random
import time

TARGET = "http://127.0.0.1:3000/attacks"   # !! Make sure this is your local test server !!
CONCURRENCY = 100        # concurrent tasks (reduce if your test VM is small)
REQUESTS_PER_TASK = 20   # number of requests each task will send
DELAY_BETWEEN_REQUESTS = (0.01, 0.2)  # randomized delay between requests (seconds)

USER_AGENTS = [
    "SimClient/1.0",
    "LoadSim/0.1",
    "TesterBot/2.3"
]

async def worker(session, id):
    for i in range(REQUESTS_PER_TASK):
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-Simulated-Client": f"sim-{id}"
        }
        try:
            async with session.get(TARGET, headers=headers, timeout=10) as resp:
                text = await resp.text()
                # optional: print minimal info for local debugging
                print(f"[task {id}] {resp.status} [{len(text)} bytes]")
        except Exception as e:
            print(f"[task {id}] error: {e}")
        await asyncio.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))

async def main():
    # Safety: confirm user intends to run locally
    print("WARNING: Run this only against your local test server. Press Enter to continue...")
    input()
    conn = aiohttp.TCPConnector(limit_per_host=CONCURRENCY)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [asyncio.create_task(worker(session, i)) for i in range(CONCURRENCY)]
        start = time.time()
        await asyncio.gather(*tasks)
        print("Done. Duration:", time.time() - start)

if __name__ == "__main__":
    asyncio.run(main())
