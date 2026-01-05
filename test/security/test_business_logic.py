import requests
import os

BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("API_KEY", "default-key-change-in-production")

def test_filter_bypass():
    """Test of filters kunnen worden omzeild"""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    tests = [
        {
            "name": "Negative studycredit",
            "payload": {"bio": "test", "studycredit": -15}
        },
        {
            "name": "Zero studycredit",
            "payload": {"bio": "test", "studycredit": 0}
        },
        {
            "name": "Huge studycredit",
            "payload": {"bio": "test", "studycredit": 999999}
        },
        {
            "name": "Invalid level",
            "payload": {"bio": "test", "level": ["INVALID_LEVEL"]}
        },
        {
            "name": "SQL in filter",
            "payload": {"bio": "test", "locations": ["'; DROP TABLE--"]}
        }
    ]
    
    print("\n=== Filter Bypass Tests ===")
    for test in tests:
        try:
            response = requests.post(
                f"{BASE_URL}/recommend",
                headers=headers,
                json=test["payload"],
                timeout=5
            )
            print(f"{test['name']}: {response.status_code}")
            if response.status_code == 200:
                print(f"  ⚠️  Potentially vulnerable!")
        except Exception as e:
            print(f"{test['name']}: Error - {e}")

def test_data_exposure():
    """Test voor data lekkage"""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    # Test met lege bio
    response = requests.post(
        f"{BASE_URL}/recommend",
        headers=headers,
        json={"bio": "", "periods": [], "locations": []}
    )
    
    print("\n=== Data Exposure Test ===")
    print(f"Empty bio status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"Results returned: {len(data)}")
        print("⚠️  Warning: Empty input returns results (potential data leak)")

if __name__ == "__main__":
    test_filter_bypass()
    test_data_exposure()