import requests

BASE_URL = "http://localhost:8000"

# 1. Verzamel informatie over endpoints
def test_endpoint_discovery():
    """Test welke endpoints beschikbaar zijn"""
    endpoints = [
        "/",
        "/docs",  # FastAPI automatic docs
        "/openapi.json",
        "/recommend",
        "/health",
        "/metrics"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{BASE_URL}{endpoint}")
            print(f"[{response.status_code}] {endpoint}")
        except Exception as e:
            print(f"[ERROR] {endpoint}: {e}")

# 2. Test headers en security headers
def test_security_headers():
    """Check voor ontbrekende security headers"""
    response = requests.post(f"{BASE_URL}/recommend")
    
    security_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy"
    ]
    
    print("\n=== Security Headers Check ===")
    for header in security_headers:
        if header in response.headers:
            print(f"✓ {header}: {response.headers[header]}")
        else:
            print(f"✗ {header}: MISSING (VULNERABILITY)")

if __name__ == "__main__":
    test_endpoint_discovery()
    test_security_headers()