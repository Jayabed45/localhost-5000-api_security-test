import requests
import json
import time
import sys
import threading
import concurrent.futures
from datetime import datetime
import urllib3

# Suppress SSL warnings if testing against https with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

class SecurityAuditor:
    def __init__(self, base_url="http://localhost:5000/api"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []
        self.admin_token = None
        self.user_token = None
        
        # Test Accounts
        self.admin_creds = {"email": "security_admin@test.com", "password": "StrongPassword123!", "name": "Security Admin"}
        self.user_creds = {"email": "security_user@test.com", "password": "StrongPassword123!", "name": "Security User"}

    def log(self, test_name, status, message=""):
        color = Colors.OKGREEN if status == "PASSED" else (Colors.FAIL if status == "FAILED" else Colors.WARNING)
        print(f"{Colors.BOLD}[{test_name}]{Colors.ENDC} {color}{status}{Colors.ENDC} {message}")
        self.results.append({
            "test": test_name,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })

    def setup_test_users(self):
        print(f"\n{Colors.HEADER}--- Setting up Test Users ---{Colors.ENDC}")
        # Create/Login Admin
        self._ensure_user(self.admin_creds, "admin")
       
        
       
        
    def _ensure_user(self, creds, role_label):
        # Try Login first
        try:
            res = self.session.post(f"{self.base_url}/auth/login", json={"email": creds["email"], "password": creds["password"]})
            if res.status_code == 200:
                token = res.json().get("token")
                if role_label == "admin": self.admin_token = token
                self.log(f"Setup {role_label}", "PASSED", "Logged in successfully")
                return

            # If login fails, try create (only works for admin based on code)
            if role_label == "admin":
                res = self.session.post(f"{self.base_url}/auth/create-admin", json=creds)
                if res.status_code in [200, 201]:
                    self.admin_token = res.json().get("token")
                    self.log(f"Setup {role_label}", "PASSED", "Created account successfully")
                else:
                    self.log(f"Setup {role_label}", "WARNING", f"Could not login or create. Status: {res.status_code}")
        except Exception as e:
            self.log(f"Setup {role_label}", "ERROR", str(e))

    def check_security_headers(self):
        print(f"\n{Colors.HEADER}1. Analyzing Security Headers...{Colors.ENDC}")
        try:
            res = self.session.get(f"{self.base_url}/health")
            headers = res.headers
            
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                "Strict-Transport-Security": None, # Value varies
                "Content-Security-Policy": None,
                "X-XSS-Protection": "1; mode=block" # Optional/Legacy but good
            }

            for header, expected in security_headers.items():
                if header in headers:
                    val = headers[header]
                    if expected:
                        if isinstance(expected, list):
                            if val in expected:
                                self.log(f"Header: {header}", "PASSED", f"Value: {val}")
                            else:
                                self.log(f"Header: {header}", "WARNING", f"Present but unexpected value: {val}")
                        else:
                            if expected in val:
                                self.log(f"Header: {header}", "PASSED", f"Value: {val}")
                            else:
                                self.log(f"Header: {header}", "WARNING", f"Present but unexpected value: {val}")
                    else:
                        self.log(f"Header: {header}", "PASSED", "Present")
                else:
                    # HSTS might be missing on localhost HTTP, which is fine
                    if header == "Strict-Transport-Security" and "localhost" in self.base_url:
                        self.log(f"Header: {header}", "SKIPPED", "Not expected on localhost/HTTP")
                    else:
                        self.log(f"Header: {header}", "FAILED", "Missing")

            # Check for information leakage headers
            leaky_headers = ["X-Powered-By", "Server"]
            for header in leaky_headers:
                if header in headers:
                    self.log(f"Leak: {header}", "WARNING", f"Reveals tech stack: {headers[header]}")
                else:
                    self.log(f"Leak: {header}", "PASSED", "Hidden")

        except Exception as e:
            self.log("Security Headers", "ERROR", str(e))

    def test_nosql_injection(self):
        print(f"\n{Colors.HEADER}2. Testing Advanced NoSQL Injection...{Colors.ENDC}")
        endpoint = f"{self.base_url}/auth/login"
        
        payloads = [
            ({"email": {"$ne": None}, "password": {"$ne": None}}, "Bypass with $ne"),
            ({"email": {"$gt": ""}, "password": {"$gt": ""}}, "Bypass with $gt"),
            ({"email": "admin@tgsbpo.com", "password": {"$regex": "^.*"}}, "Regex Injection")
        ]

        for payload, name in payloads:
            try:
                res = self.session.post(endpoint, json=payload)
                if res.status_code == 200 and "token" in res.json():
                    self.log(f"Injection: {name}", "FAILED", "Login Successful (VULNERABLE)")
                else:
                    self.log(f"Injection: {name}", "PASSED", f"Rejected (Status: {res.status_code})")
            except Exception as e:
                self.log(f"Injection: {name}", "ERROR", str(e))

    def test_jwt_weaknesses(self):
        print(f"\n{Colors.HEADER}3. Testing JWT Security...{Colors.ENDC}")
        if not self.admin_token:
            self.log("JWT Tests", "SKIPPED", "No valid token available")
            return

        # Test 1: Tampered Payload (Signature Mismatch)
        parts = self.admin_token.split('.')
        if len(parts) == 3:
            tampered_token = f"{parts[0]}.{parts[1]}Changed.{parts[2]}"
            res = self.session.get(f"{self.base_url}/auth/profile", headers={"Authorization": f"Bearer {tampered_token}"})
            if res.status_code == 401 or res.status_code == 403:
                self.log("JWT Tampering", "PASSED", "Rejected invalid signature")
            else:
                self.log("JWT Tampering", "FAILED", f"Accepted tampered token (Status: {res.status_code})")

        # Test 2: 'None' Algorithm (If library is vulnerable)
        # This requires constructing a token with alg: none. 
        # Simplified check: just modify header to eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0 ({"alg":"none","typ":"JWT"})
        none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
        none_token = f"{none_header}.{parts[1]}." # No signature
        res = self.session.get(f"{self.base_url}/auth/profile", headers={"Authorization": f"Bearer {none_token}"})
        if res.status_code == 401 or res.status_code == 403:
            self.log("JWT None Algo", "PASSED", "Rejected 'none' algorithm")
        else:
            self.log("JWT None Algo", "FAILED", f"Accepted 'none' algorithm (Status: {res.status_code})")

    def test_rate_limiting_concurrent(self):
        print(f"\n{Colors.HEADER}4. Testing Rate Limiting (Concurrent)...{Colors.ENDC}")
        endpoint = f"{self.base_url}/auth/login"
        payload = {"email": "attacker@example.com", "password": "wrongpassword"}
        
        request_count = 50
        print(f"   Launching {request_count} concurrent requests...")
        
        status_codes = []
        
        def make_request():
            try:
                res = requests.post(endpoint, json=payload)
                return res.status_code
            except:
                return 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(request_count)]
            for future in concurrent.futures.as_completed(futures):
                status_codes.append(future.result())
        
        blocked_count = status_codes.count(429)
        success_count = status_codes.count(200) + status_codes.count(401) # 401 is success in reaching app logic
        
        print(f"   Results: {blocked_count} Blocked, {success_count} Processed")
        
        if blocked_count > 0:
            self.log("Rate Limiting", "PASSED", f"Blocked {blocked_count} requests")
        else:
            self.log("Rate Limiting", "FAILED", "No requests were blocked (Threshold likely > 50)")

    def test_xss_and_input(self):
        print(f"\n{Colors.HEADER}5. Testing Input Validation (XSS)...{Colors.ENDC}")
        endpoint = f"{self.base_url}/auth/login"
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "\"><img src=x onerror=alert(1)>"
        ]
        
        for payload in xss_payloads:
            data = {"email": payload, "password": "password"}
            res = self.session.post(endpoint, json=data)
            
            # We check if 500 (crash) or if reflected (hard in JSON API, but we check generic handling)
            if res.status_code == 500:
                self.log(f"XSS Handling: {payload[:15]}...", "FAILED", "Server Error (500) - Potential crash")
            elif res.status_code == 429:
                 self.log(f"XSS Handling: {payload[:15]}...", "PASSED", "Blocked by Rate Limiter (Safe)")
            elif res.status_code in [400, 401]:
                self.log(f"XSS Handling: {payload[:15]}...", "PASSED", "Handled gracefully")
            else:
                self.log(f"XSS Handling: {payload[:15]}...", "WARNING", f"Status {res.status_code}")

    def test_error_disclosure(self):
        print(f"\n{Colors.HEADER}6. Testing Error Disclosure...{Colors.ENDC}")
        # Send malformed JSON
        res = requests.post(f"{self.base_url}/auth/login", data="{'invalid': json", headers={"Content-Type": "application/json"})
        
        if "SyntaxError" in res.text or "constant" in res.text or r"c:\Users" in res.text:
             self.log("Stack Trace Disclosure", "FAILED", "Stack trace or internal path revealed")
        else:
             self.log("Stack Trace Disclosure", "PASSED", "No obvious stack trace in response")

    def run(self):
        print(f"{Colors.BOLD}Starting Professional Security Audit{Colors.ENDC}")
        print(f"Target: {self.base_url}")
        print("-" * 60)
        
        if not self._check_health():
            print("Target is down. Aborting.")
            return

        self.setup_test_users()
        self.check_security_headers()
        self.test_nosql_injection()
        self.test_jwt_weaknesses()
        self.test_xss_and_input()
        self.test_error_disclosure()
        self.test_rate_limiting_concurrent()
        
        print("-" * 60)
        print(f"{Colors.BOLD}Audit Complete.{Colors.ENDC}")

    def _check_health(self):
        try:
            requests.get(f"{self.base_url}/health", timeout=5)
            return True
        except:
            return False

if __name__ == "__main__":
    auditor = SecurityAuditor()
    auditor.run()
