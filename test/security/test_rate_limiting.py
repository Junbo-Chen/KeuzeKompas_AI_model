import requests
import concurrent.futures
import time
import os
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("API_KEY")

def test_rate_limiting():
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {"bio": "test", "periods": [], "locations": []}

    print("\n=== Rate Limiting Test ===")
    print("Sending 110 requests rapidly...")

    status_counts = {}  # ✅ HIER, buiten de loop

    start = time.time()

    for i in range(110):
        response = requests.post(
            f"{BASE_URL}/recommend",
            headers=headers,
            json=payload
        )

        code = response.status_code
        status_counts[code] = status_counts.get(code, 0) + 1

        if (i + 1) % 50 == 0:
            print(f"  {i + 1} requests sent...")

    elapsed = time.time() - start

    print("\nResults:")
    for code, count in sorted(status_counts.items()):
        print(f"  {code}: {count}")

    print(
        f"\nRate limiting "
        f"{'WORKING ✓' if status_counts.get(429, 0) > 0 else 'NOT WORKING ✗'}"
    )


def test_concurrent_requests():
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {"bio": "test", "periods": [], "locations": []}

    def make_request(_):
        r = requests.post(
            f"{BASE_URL}/recommend",
            headers=headers,
            json=payload,
            timeout=30
        )
        return r.status_code

    print("\n=== Concurrent Requests Test ===")
    print("Sending 110 concurrent requests...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(make_request, range(110)))

    status_counts = {}
    for code in results:
        status_counts[code] = status_counts.get(code, 0) + 1

    print("\nResults:")
    for code, count in sorted(status_counts.items()):
        print(f"  {code}: {count}")

    print(
        f"\nRate limiting "
        f"{'WORKING ✓' if status_counts.get(429, 0) > 0 else 'NOT WORKING ✗'}"
    )

if __name__ == "__main__":
    test_rate_limiting()
    time.sleep(60)  # Wait for rate limit to reset
    test_concurrent_requests()