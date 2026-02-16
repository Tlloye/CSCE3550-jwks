import base64
import json
import time
import unittest
import subprocess
import urllib.request
import urllib.error

SERVER_URL = "http://localhost:8080"

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

def jwt_parts(token: str):
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]).decode())
    payload = json.loads(b64url_decode(parts[1]).decode())
    sig = parts[2]
    return header, payload, sig

def http_get(path: str):
    with urllib.request.urlopen(SERVER_URL + path, timeout=3) as r:
        return r.status, r.read().decode()

def http_post(path: str):
    req = urllib.request.Request(SERVER_URL + path, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.status, r.read().decode()

def http_get_error_code(path: str):
    try:
        http_get(path)
        return None
    except urllib.error.HTTPError as e:
        return e.code

class TestJWKS(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["pkill", "jwks"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.proc = subprocess.Popen(["./jwks"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.4)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def test_root(self):
        status, body = http_get("/")
        self.assertEqual(status, 200)
        self.assertIn("JWKS Server Running", body)

    def test_jwks_filters_expired(self):
        status, body = http_get("/.well-known/jwks.json")
        self.assertEqual(status, 200)
        data = json.loads(body)
        kids = [k.get("kid") for k in data.get("keys", [])]
        self.assertIn("valid-kid", kids)
        self.assertNotIn("expired-kid", kids)

    def test_auth_valid(self):
        status, body = http_post("/auth")
        self.assertEqual(status, 200)
        data = json.loads(body)
        header, payload, sig = jwt_parts(data["token"])
        self.assertEqual(header["kid"], "valid-kid")
        self.assertTrue(len(sig) > 20)
        self.assertGreater(payload["exp"], int(time.time()))

    def test_auth_expired(self):
        status, body = http_post("/auth?expired=true")
        self.assertEqual(status, 200)
        data = json.loads(body)
        header, payload, sig = jwt_parts(data["token"])
        self.assertEqual(header["kid"], "expired-kid")
        self.assertTrue(len(sig) > 20)
        self.assertLess(payload["exp"], int(time.time()))

    def test_get_auth_405(self):
        code = http_get_error_code("/auth")
        self.assertEqual(code, 405)

if __name__ == "__main__":
    unittest.main(verbosity=2)


