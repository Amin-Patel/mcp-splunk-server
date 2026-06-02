"""
Direct test of Splunk connection.
Tests both Free Mode (no auth) and Auth Mode.
"""

import os
import sys
import splunklib.client as client
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("=" * 60)
print("SPLUNK CONNECTION DIAGNOSTIC")
print("=" * 60)

# ----------------------------------------------------------
# TEST 1: FREE MODE (no auth)
# ----------------------------------------------------------
print("\n[TEST 1] Trying FREE MODE (no authentication)...")
try:
    service = client.connect(
        host="localhost",
        port=8089,
        scheme="https",
        verify=False
    )
    info = service.info
    print("✅ FREE MODE WORKS!")
    print(f"   Server: {info.get('serverName')}")
    print(f"   Version: {info.get('version')}")
    print(f"   Indexes: {len(service.indexes)}")
except Exception as e:
    print(f"❌ FREE MODE FAILED: {str(e)}")

# ----------------------------------------------------------
# TEST 2: AUTH MODE with admin/changeme
# ----------------------------------------------------------
print("\n[TEST 2] Trying AUTH MODE with admin:changeme...")
try:
    service = client.connect(
        host="localhost",
        port=8089,
        username="admin",
        password="changeme",
        scheme="https",
        verify=False
    )
    info = service.info
    print("✅ AUTH MODE WORKS with admin:changeme")
    print(f"   Server: {info.get('serverName')}")
except Exception as e:
    print(f"❌ AUTH MODE FAILED: {str(e)}")

# ----------------------------------------------------------
# TEST 3: AUTH MODE with admin/admin
# ----------------------------------------------------------
print("\n[TEST 3] Trying AUTH MODE with admin:admin...")
try:
    service = client.connect(
        host="localhost",
        port=8089,
        username="admin",
        password="admin",
        scheme="https",
        verify=False
    )
    info = service.info
    print("✅ AUTH MODE WORKS with admin:admin")
    print(f"   Server: {info.get('serverName')}")
except Exception as e:
    print(f"❌ AUTH MODE FAILED: {str(e)}")

# ----------------------------------------------------------
# TEST 4: Check what env vars Claude is passing
# ----------------------------------------------------------
print("\n[TEST 4] Current environment variables:")
print(f"   SPLUNK_HOST: {os.getenv('SPLUNK_HOST', 'NOT SET')}")
print(f"   SPLUNK_PORT: {os.getenv('SPLUNK_PORT', 'NOT SET')}")
print(f"   SPLUNK_FREE_MODE: {os.getenv('SPLUNK_FREE_MODE', 'NOT SET')}")
print(f"   SPLUNK_USERNAME: {os.getenv('SPLUNK_USERNAME', 'NOT SET')}")
print(f"   SPLUNK_PASSWORD: {'***SET***' if os.getenv('SPLUNK_PASSWORD') else 'NOT SET'}")

print("\n" + "=" * 60)
print("DIAGNOSTIC COMPLETE")
print("=" * 60)