"""
Test script for VigilEdge Authentication System
"""

import requests
import json

def test_authentication():
    base_url = "http://127.0.0.1:5000"
    
    print("🔧 Testing VigilEdge Authentication System...")
    print("=" * 50)
    
    # Test 1: Access root without authentication (should redirect to login)
    print("\n1. Testing unauthenticated access to root...")
    response = requests.get(f"{base_url}/", allow_redirects=False)
    print(f"   Status: {response.status_code}")
    if response.status_code == 302:
        print(f"   ✅ Correctly redirected to: {response.headers.get('location', 'unknown')}")
    else:
        print(f"   ❌ Expected 302 redirect")
    
    # Test 2: Test login page access
    print("\n2. Testing login page access...")
    response = requests.get(f"{base_url}/login")
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        print("   ✅ Login page accessible")
    else:
        print("   ❌ Login page not accessible")
    
    # Test 3: Test admin login
    print("\n3. Testing admin login...")
    login_data = {
        "username": "admin",
        "password": "admin123",
        "remember_me": False
    }
    response = requests.post(f"{base_url}/login", json=login_data)
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"   ✅ Admin login successful")
        print(f"   Role: {result.get('role')}")
        print(f"   Username: {result.get('username')}")
        admin_token = result.get('token')
        
        # Test 4: Test admin dashboard access
        print("\n4. Testing admin dashboard access...")
        headers = {'Cookie': f'session_token={admin_token}'}
        response = requests.get(f"{base_url}/admin/dashboard", headers=headers, allow_redirects=False)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Admin dashboard accessible")
        else:
            print(f"   ❌ Admin dashboard not accessible: {response.text[:100]}")
    else:
        print(f"   ❌ Admin login failed: {response.text}")
        admin_token = None
    
    # Test 5: Test customer login
    print("\n5. Testing customer login...")
    login_data = {
        "username": "demo_customer",
        "password": "customer123",
        "remember_me": False
    }
    response = requests.post(f"{base_url}/login", json=login_data)
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"   ✅ Customer login successful")
        print(f"   Role: {result.get('role')}")
        print(f"   Username: {result.get('username')}")
        customer_token = result.get('token')
        
        # Test 6: Test customer dashboard access
        print("\n6. Testing customer dashboard access...")
        headers = {'Cookie': f'session_token={customer_token}'}
        response = requests.get(f"{base_url}/dashboard", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Customer dashboard accessible")
        else:
            print(f"   ❌ Customer dashboard not accessible")
        
        # Test 7: Test customer trying to access admin dashboard
        print("\n7. Testing customer access to admin dashboard (should fail)...")
        response = requests.get(f"{base_url}/admin/dashboard", headers=headers, allow_redirects=False)
        print(f"   Status: {response.status_code}")
        if response.status_code == 403:
            print("   ✅ Customer correctly denied admin access")
        else:
            print(f"   ❌ Customer access not properly restricted")
    else:
        print(f"   ❌ Customer login failed: {response.text}")
    
    # Test 8: Test invalid login
    print("\n8. Testing invalid login...")
    login_data = {
        "username": "invalid",
        "password": "wrong",
        "remember_me": False
    }
    response = requests.post(f"{base_url}/login", json=login_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 401:
        print("   ✅ Invalid login correctly rejected")
    else:
        print(f"   ❌ Invalid login not properly handled")
    
    print("\n" + "=" * 50)
    print("🎉 Authentication testing completed!")

if __name__ == "__main__":
    try:
        test_authentication()
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to VigilEdge server at http://127.0.0.1:5000")
        print("   Make sure the server is running with: python main.py")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
