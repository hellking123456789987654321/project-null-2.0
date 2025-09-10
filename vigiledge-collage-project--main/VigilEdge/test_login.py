#!/usr/bin/env python3
"""
Simple test script to verify VigilEdge authentication
"""

import requests
import json

def test_login():
    """Test the login functionality"""
    login_url = "http://127.0.0.1:5000/login"
    
    # Test data
    login_data = {
        "username": "admin",
        "password": "admin123", 
        "remember_me": False
    }
    
    try:
        # Test GET request to login page
        print("Testing GET /login...")
        get_response = requests.get(login_url)
        print(f"GET Status: {get_response.status_code}")
        if get_response.status_code == 200:
            print("✅ Login page accessible")
        else:
            print(f"❌ Login page error: {get_response.text}")
            
        # Test POST request for authentication
        print("\nTesting POST /login...")
        headers = {"Content-Type": "application/json"}
        post_response = requests.post(login_url, json=login_data, headers=headers)
        print(f"POST Status: {post_response.status_code}")
        
        if post_response.status_code == 200:
            response_data = post_response.json()
            print("✅ Login successful!")
            print(f"Response: {json.dumps(response_data, indent=2)}")
            print(f"Cookies: {post_response.cookies}")
        else:
            print(f"❌ Login failed: {post_response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Is it running on port 5000?")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_login()
