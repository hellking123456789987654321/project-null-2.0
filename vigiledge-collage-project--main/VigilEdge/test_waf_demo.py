#!/usr/bin/env python3
"""
VigilEdge WAF Attack Demonstration Script
This script demonstrates various attacks against the vulnerable application
and shows how the WAF blocks them.
"""

import asyncio
import httpx
import json
from typing import Dict, List
import time

class WAFTester:
    def __init__(self):
        self.waf_url = "http://localhost:5000"
        self.target_url = "http://localhost:8080"
        self.test_results = []
    
    async def test_direct_vs_waf(self, endpoint: str, attack_payload: str, attack_type: str):
        """Test attack directly vs through WAF"""
        print(f"\n🎯 Testing {attack_type}")
        print(f"   Endpoint: {endpoint}")
        print(f"   Payload: {attack_payload}")
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Test direct attack (should succeed)
            try:
                direct_url = f"{self.target_url}{endpoint}"
                print(f"\n📡 Direct attack: {direct_url}")
                direct_response = await client.get(direct_url)
                direct_success = direct_response.status_code == 200
                print(f"   Status: {direct_response.status_code}")
                print(f"   Result: {'✅ Attack succeeded' if direct_success else '❌ Attack failed'}")
            except Exception as e:
                print(f"   Error: {e}")
                direct_success = False
            
            # Small delay
            await asyncio.sleep(1)
            
            # Test through WAF (should be blocked)
            try:
                waf_url = f"{self.waf_url}/api/v1/test{endpoint}"
                print(f"\n🛡️  WAF-protected: {waf_url}")
                waf_response = await client.get(waf_url)
                waf_blocked = waf_response.status_code == 403
                print(f"   Status: {waf_response.status_code}")
                print(f"   Result: {'🛡️  Attack blocked by WAF' if waf_blocked else '⚠️  Attack not blocked'}")
                
                if waf_blocked:
                    try:
                        error_data = waf_response.json()
                        print(f"   Reason: {error_data.get('reason', 'Unknown')}")
                    except:
                        pass
                
            except Exception as e:
                print(f"   Error: {e}")
                waf_blocked = False
            
            # Record results
            self.test_results.append({
                "attack_type": attack_type,
                "endpoint": endpoint,
                "payload": attack_payload,
                "direct_success": direct_success,
                "waf_blocked": waf_blocked,
                "protection_effective": direct_success and waf_blocked
            })
    
    async def test_sql_injection(self):
        """Test SQL injection attacks"""
        sql_tests = [
            ("/products?id=1' OR 1=1--", "' OR 1=1--", "SQL Injection - OR condition"),
            ("/products?id=1; DROP TABLE users;--", "; DROP TABLE users;--", "SQL Injection - DROP TABLE"),
            ("/products?search=' UNION SELECT * FROM users--", "' UNION SELECT", "SQL Injection - UNION SELECT"),
        ]
        
        for endpoint, payload, attack_type in sql_tests:
            await self.test_direct_vs_waf(endpoint, payload, attack_type)
            await asyncio.sleep(2)  # Pause between tests
    
    async def test_xss_attacks(self):
        """Test XSS attacks"""
        xss_tests = [
            ("/?search=<script>alert('XSS')</script>", "<script>alert('XSS')</script>", "XSS - Script tag"),
            ("/?search=<img src=x onerror=alert('XSS')>", "<img src=x onerror=alert('XSS')>", "XSS - Image onerror"),
            ("/?search=<svg onload=alert('XSS')></svg>", "<svg onload=alert('XSS')></svg>", "XSS - SVG onload"),
        ]
        
        for endpoint, payload, attack_type in xss_tests:
            await self.test_direct_vs_waf(endpoint, payload, attack_type)
            await asyncio.sleep(2)
    
    async def test_directory_traversal(self):
        """Test directory traversal attacks"""
        traversal_tests = [
            ("/file?path=../../../etc/passwd", "../../../etc/passwd", "Directory Traversal - Linux passwd"),
            ("/file?path=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "..\\..\\..\\windows\\hosts", "Directory Traversal - Windows hosts"),
            ("/file?path=....//....//....//etc/passwd", "....//....//....//etc/passwd", "Directory Traversal - Double encoding"),
        ]
        
        for endpoint, payload, attack_type in traversal_tests:
            await self.test_direct_vs_waf(endpoint, payload, attack_type)
            await asyncio.sleep(2)
    
    async def check_services(self):
        """Check if both services are running"""
        print("🔍 Checking service status...")
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Check vulnerable app
            try:
                response = await client.get(f"{self.target_url}/health")
                if response.status_code == 200:
                    print("✅ Vulnerable target app is running on port 8080")
                else:
                    print("❌ Vulnerable target app responded with error")
                    return False
            except Exception as e:
                print(f"❌ Vulnerable target app is not accessible: {e}")
                print("   Start it with: python vulnerable_app.py")
                return False
            
            # Check WAF
            try:
                response = await client.get(f"{self.waf_url}/health")
                if response.status_code == 200:
                    print("✅ VigilEdge WAF is running on port 5000")
                else:
                    print("❌ WAF responded with error")
                    return False
            except Exception as e:
                print(f"❌ VigilEdge WAF is not accessible: {e}")
                print("   Start it with: python main.py")
                return False
        
        return True
    
    async def run_tests(self):
        """Run all attack tests"""
        print("🎯 VigilEdge WAF Attack Demonstration")
        print("=" * 50)
        
        # Check services first
        if not await self.check_services():
            return
        
        print("\n🚀 Starting attack simulations...")
        print("This will demonstrate how the WAF protects against various attacks.")
        
        # Run attack tests
        await self.test_sql_injection()
        await self.test_xss_attacks()
        await self.test_directory_traversal()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate test results report"""
        print("\n" + "=" * 50)
        print("📊 WAF PROTECTION REPORT")
        print("=" * 50)
        
        total_tests = len(self.test_results)
        effective_protection = sum(1 for result in self.test_results if result["protection_effective"])
        
        print(f"\nTotal attack tests: {total_tests}")
        print(f"Effective protection: {effective_protection}/{total_tests}")
        print(f"Protection rate: {(effective_protection/total_tests)*100:.1f}%")
        
        print("\n📋 Detailed Results:")
        for i, result in enumerate(self.test_results, 1):
            status = "🛡️  PROTECTED" if result["protection_effective"] else "⚠️  NOT PROTECTED"
            print(f"{i:2d}. {result['attack_type']}: {status}")
            print(f"     Direct attack: {'✅ Success' if result['direct_success'] else '❌ Failed'}")
            print(f"     WAF blocking: {'✅ Blocked' if result['waf_blocked'] else '❌ Allowed'}")
        
        if effective_protection == total_tests:
            print("\n🎉 Excellent! Your WAF is protecting against all tested attacks!")
        elif effective_protection > total_tests * 0.8:
            print("\n👍 Good protection rate, but some attacks may need attention.")
        else:
            print("\n⚠️  Warning: WAF may need configuration adjustments.")
        
        print("\n💡 Next steps:")
        print("   • Check WAF dashboard for real-time alerts")
        print("   • Review security logs in logs/vigiledge.log")
        print("   • Monitor blocked IPs and attack patterns")
        print("   • Adjust WAF rules if needed")

async def main():
    """Main demonstration function"""
    tester = WAFTester()
    await tester.run_tests()

if __name__ == "__main__":
    print("🛡️  VigilEdge WAF Testing Suite")
    print("Make sure both applications are running:")
    print("1. python vulnerable_app.py  (port 8080)")
    print("2. python main.py             (port 5000)")
    print("\nStarting tests in 3 seconds...")
    time.sleep(3)
    
    asyncio.run(main())
