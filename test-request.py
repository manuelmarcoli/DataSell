import requests
import sys

try:
    response = requests.get('http://localhost:3000/login', timeout=3)
    print(f"✅ Status: {response.status_code}")
    print(f"Content length: {len(response.text)} bytes")
    print(f"First 200 chars: {response.text[:200]}")
except Exception as e:
    print(f"❌ Error: {e}", file=sys.stderr)
    sys.exit(1)
