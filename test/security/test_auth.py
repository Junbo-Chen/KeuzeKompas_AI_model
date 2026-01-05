import requests

BASE_URL = "http://localhost:8000"

def test_no_api_key():
    """Test toegang zonder API key"""
    response = requests.post(
        f"{BASE_URL}/recommend",
        json={"bio": "test", "periods": [], "locations": []}
    )
    print(f"No API key: {response.status_code} (Should be 401)")
    
def test_invalid_api_key():
    """Test met foute API key"""
    response = requests.post(
        f"{BASE_URL}/recommend",
        headers={"Authorization": "Bearer wrong-key-12345"},
        json={"bio": "test", "periods": [], "locations": []}
    )
    print(f"Invalid API key: {response.status_code} (Should be 401)")

def test_sql_injection_in_api_key():
    """Test SQL injection in API key"""
    payloads = [
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--"
    ]
    
    for payload in payloads:
        response = requests.post(
            f"{BASE_URL}/recommend",
            headers={"Authorization": f"Bearer {payload}"},
            json={"bio": "test", "periods": [], "locations": []}
        )
        print(f"SQLi payload '{payload}': {response.status_code}")

if __name__ == "__main__":
    test_no_api_key()
    test_invalid_api_key()
    test_sql_injection_in_api_key()