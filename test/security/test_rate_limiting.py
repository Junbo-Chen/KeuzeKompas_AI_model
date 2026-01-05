import requests
import concurrent.futures
import time
import os

BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("API_KEY", "default-key-change-in-production")

def test_rate_limiting():
    """Test of rate limiting werkt"""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    payload = {"bio": "test", "periods": [], "locations": []}
    
    print("\n=== Rate Limiting Test ===")
    print("Sending 150 requests rapidly...")
    
    success_count = 0
    rate_limited_count = 0
    
    start = time.time()
    
    for i in range(150):
        response = requests.post(
            f"{BASE_URL}/recommend",
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:  # Too Many Requests
            rate_limited_count += 1
        
        if (i + 1) % 50 == 0:
            print(f"  {i + 1} requests sent...")
    
    elapsed = time.time() - start
    
    print(f"\nResults:")
    print(f"  Total time: {elapsed:.2f}s")
    print(f"  Successful: {success_count}")
    print(f"  Rate limited: {rate_limited_count}")
    print(f"  Rate limiting {'WORKING ✓' if rate_limited_count > 0 else 'NOT WORKING ✗'}")

def test_concurrent_requests():
    """Test met parallelle requests"""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    payload = {"bio": "test", "periods": [], "locations": []}
    
    def make_request(i):
        try:
            response = requests.post(
                f"{BASE_URL}/recommend",
                headers=headers,
                json=payload,
                timeout=10
            )
            return response.status_code
        except Exception as e:
            return f"Error: {e}"
    
    print("\n=== Concurrent Requests Test ===")
    print("Sending 50 concurrent requests...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(make_request, range(50)))
    
    status_codes = {}
    for code in results:
        status_codes[code] = status_codes.get(code, 0) + 1
    
    print("\nResults:")
    for code, count in sorted(status_codes.items()):
        print(f"  {code}: {count} requests")

if __name__ == "__main__":
    test_rate_limiting()
    time.sleep(60)  # Wait for rate limit to reset
    test_concurrent_requests()