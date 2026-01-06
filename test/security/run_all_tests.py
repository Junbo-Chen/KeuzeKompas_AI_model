import sys
import os

# Set API key for tests
os.environ["API_KEY"] = os.getenv("API_KEY", "default-key-change-in-production")

# Import all test modules
from test_auth import test_no_api_key, test_invalid_api_key, test_sql_injection_in_api_key
from test_input_validation import test_injection_attacks, test_oversized_input, test_special_characters
from test_rate_limiting import test_rate_limiting, test_concurrent_requests
from test_business_logic import test_filter_bypass, test_data_exposure
from test_reconnaissance import test_endpoint_discovery, test_security_headers

def run_test_suite(test_func, test_name):
    """Run a test and handle exceptions"""
    print(f"\n{'='*60}")
    print(f"Running: {test_name}")
    print(f"{'='*60}")
    try:
        test_func()
        print(f"✓ {test_name} completed")
        return True
    except AssertionError as e:
        print(f"✗ {test_name} FAILED: {e}")
        return False
    except Exception as e:
        print(f"✗ {test_name} ERROR: {e}")
        return False

def main():
    """Run all security tests"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║          KeuzeKompas API Security Test Suite                 ║
║                                                              ║
║  Make sure the API is running on http://localhost:8000      ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Check if API is running
    import requests
    try:
        response = requests.get("http://localhost:8000/docs", timeout=2)
        if response.status_code != 200:
            print("⚠️  Warning: API may not be running properly")
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to API at http://localhost:8000")
        print("   Please start the API with: uvicorn app.main:app --reload")
        sys.exit(1)
    
    results = []
    
    # Authentication Tests
    results.append(run_test_suite(test_no_api_key, "Authentication: No API Key"))
    results.append(run_test_suite(test_invalid_api_key, "Authentication: Invalid API Key"))
    results.append(run_test_suite(test_sql_injection_in_api_key, "Authentication: SQL Injection"))
    
    # Input Validation Tests
    results.append(run_test_suite(test_injection_attacks, "Input Validation: Injection Attacks"))
    results.append(run_test_suite(test_oversized_input, "Input Validation: Oversized Input"))
    results.append(run_test_suite(test_special_characters, "Input Validation: Special Characters"))
    
    # Rate Limiting Tests
    results.append(run_test_suite(test_rate_limiting, "Rate Limiting: Basic Test"))
    results.append(run_test_suite(test_concurrent_requests, "Rate Limiting: Concurrent Requests"))
    
    # Business Logic Tests
    results.append(run_test_suite(test_filter_bypass, "Business Logic: Filter Bypass"))
    results.append(run_test_suite(test_data_exposure, "Business Logic: Data Exposure"))
    
    # Reconnaissance Tests
    results.append(run_test_suite(test_endpoint_discovery, "Reconnaissance: Endpoint Discovery"))
    results.append(run_test_suite(test_security_headers, "Reconnaissance: Security Headers"))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(results)
    total = len(results)
    failed = total - passed
    
    print(f"\nTotal Tests: {total}")
    print(f"✓ Passed: {passed}")
    print(f"✗ Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 All security tests passed!")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())