import unittest
import requests
import json
import time

class TestJWKSAuthServer(unittest.TestCase):
    SERVER_URL = "http://localhost:8080"
    
    def test_user_registration(self):
        # Test user registration endpoint
        register_url = f"{self.SERVER_URL}/register"
        payload = {"username": "test_user", "email": "test@example.com"}
        response = requests.post(register_url, json=payload)
        self.assertIn(response.status_code, [200, 201])
        data = json.loads(response.text)
        self.assertIn("password", data)

    def test_authentication_rate_limiting(self):
        # Test authentication rate limiting
        auth_url = f"{self.SERVER_URL}/auth"
        payload = {}  # No authentication payload needed for this test
        headers = {'Content-type': 'application/json'}
        
        # Send more than 10 requests within 1 second
        for i in range(11):
            response = requests.post(auth_url, json=payload, headers=headers)
            if i < 10:
                self.assertEqual(response.status_code, 200)
            else:
                self.assertEqual(response.status_code, 429)
            time.sleep(0.1)  # Wait for 0.1 seconds between requests

    def test_jwks_endpoint(self):
        # Test JWKS endpoint response
        jwks_url = f"{self.SERVER_URL}/.well-known/jwks.json"
        response = requests.get(jwks_url)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.text)
        self.assertIn("keys", data)
        self.assertTrue(isinstance(data["keys"], list))
        self.assertTrue(len(data["keys"]) > 0)
        self.assertTrue(all(key.get("kid") for key in data["keys"]))
        self.assertTrue(all(key.get("n") for key in data["keys"]))
        self.assertTrue(all(key.get("e") for key in data["keys"]))

if __name__ == '__main__':
    unittest.main()
