import requests
import os

BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("API_KEY")

def test_injection_attacks():
    """Test verschillende injection attacks"""
    
    injection_payloads = {
        "XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ],
        "SQL Injection": [
            "' OR '1'='1",
            "'; DROP TABLE modules;--",
            "1' UNION SELECT NULL--"
        ],
        "Command Injection": [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`"
        ],
        "Path Traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "....//....//....//etc/passwd"
        ],
        "NoSQL Injection": [
            "{'$gt': ''}",
            "{'$ne': null}",
            "'; return true; var dummy='"
        ]
    }
    
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    print("\n=== Injection Attack Tests ===")
    for attack_type, payloads in injection_payloads.items():
        print(f"\n{attack_type}:")
        for payload in payloads:
            try:
                response = requests.post(
                    f"{BASE_URL}/recommend",
                    headers=headers,
                    json={"bio": payload, "periods": [], "locations": []},
                    timeout=5
                )
                print(f"  Payload: {payload[:50]}...")
                print(f"  Status: {response.status_code}")
                if response.status_code == 200:
                    print(f"  ⚠️  WARNING: Payload accepted!")
            except Exception as e:
                print(f"  Error: {e}")

def test_oversized_input():
    """Test met te grote input"""
    payloads = [
        "A" * 5000,    # 5KB
        "A" * 50000,   # 50KB
        "A" * 500000,  # 500KB
    ]
    
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    print("\n=== Oversized Input Tests ===")
    for size_desc, payload in zip(["5KB", "50KB", "500KB"], payloads):
        try:
            response = requests.post(
                f"{BASE_URL}/recommend",
                headers=headers,
                json={"bio": payload, "periods": [], "locations": []},
                timeout=10
            )
            print(f"{size_desc}: {response.status_code}")
        except Exception as e:
            print(f"{size_desc}: Error - {e}")

def test_special_characters():
    """Test met speciale karakters"""
    payloads = [
        "测试中文字符",
        "тест русский",
        "🔥💯🚀",
        "\x00\x01\x02",  # Null bytes
        "\n\r\t",
        "'; alert('xss'); //",
    ]
    
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    print("\n=== Special Characters Tests ===")
    for payload in payloads:
        try:
            response = requests.post(
                f"{BASE_URL}/recommend",
                headers=headers,
                json={"bio": payload, "periods": [], "locations": []},
                timeout=5
            )
            print(f"Payload: {repr(payload)[:50]}... - Status: {response.status_code}")
        except Exception as e:
            print(f"Payload: {repr(payload)[:50]}... - Error: {e}")

if __name__ == "__main__":
    test_injection_attacks()
    test_oversized_input()
    test_special_characters()