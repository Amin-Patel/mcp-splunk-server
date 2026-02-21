"""
============================================================
SPLUNK CONFIGURATION MODULE
============================================================
Project: MCP Server for Splunk
Author: Sayyed Abuzar (Team Lead)
Purpose: Handle Splunk connection settings and create
         a reusable connection to Splunk.

This module:
1. Reads credentials from .env file
2. Creates a Splunk service connection
3. Provides helper functions for common operations
============================================================
"""

# Import required libraries
import os                          # For reading environment variables
import sys                         # For system operations
from dotenv import load_dotenv     # For reading .env file
import splunklib.client as client  # Splunk SDK — creates connection
import urllib3                     # For suppressing SSL warnings

# Suppress SSL warnings (Splunk uses self-signed certificate locally)
# This is SAFE for local development — we'd use proper certs in production
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from .env file
# This reads C:\MCP_Project\.env and makes variables available
load_dotenv()


def get_splunk_config():
    """
    Read Splunk configuration from .env file.
    
    Returns:
        dict: Dictionary containing all Splunk connection settings
    
    Why a function?
    → We might want to change how we read config later
    → Maybe from a database, or from command line arguments
    → Having it in a function makes it easy to swap
    """
    config = {
        "host": os.getenv("SPLUNK_HOST", "localhost"),
        "port": int(os.getenv("SPLUNK_PORT", 8089)),
        "username": os.getenv("SPLUNK_USERNAME", "admin"),
        "password": os.getenv("SPLUNK_PASSWORD", ""),
        "web_port": int(os.getenv("SPLUNK_WEB_PORT", 8000)),
        "default_index": os.getenv("SPLUNK_DEFAULT_INDEX", "security"),
        "test_index": os.getenv("SPLUNK_TEST_INDEX", "mcp_test"),
        "verify_ssl": os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true",
    }
    
    # Validate that password is not empty
    if not config["password"]:
        print("❌ ERROR: SPLUNK_PASSWORD is not set in .env file!")
        print("   Please add your Splunk admin password to .env")
        sys.exit(1)
    
    return config


def connect_to_splunk():
    """
    Create and return a connection to Splunk.
    
    Returns:
        splunklib.client.Service: A connected Splunk service object
    
    This is the MAIN function other scripts will use.
    Once connected, you can:
    → Run searches
    → Get alerts
    → Check server status
    → And everything else our MCP tools will do
    """
    config = get_splunk_config()
    
    try:
        # Create connection to Splunk
        # This is like logging into Splunk, but from code
        service = client.connect(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            autologin=True  # Automatically re-login if session expires
        )
        
        return service
    
    except ConnectionRefusedError:
        print("❌ ERROR: Cannot connect to Splunk!")
        print(f"   Tried connecting to {config['host']}:{config['port']}")
        print("   Is Splunk running? Check http://localhost:8000")
        sys.exit(1)
    
    except Exception as e:
        print(f"❌ ERROR: Splunk connection failed!")
        print(f"   Error type: {type(e).__name__}")
        print(f"   Error message: {str(e)}")
        print()
        print("   Common fixes:")
        print("   1. Make sure Splunk is running (check localhost:8000)")
        print("   2. Check username/password in .env file")
        print("   3. Check that port 8089 is not blocked")
        sys.exit(1)


def test_connection():
    """
    Test the Splunk connection and print server info.
    
    This function:
    1. Connects to Splunk
    2. Gets server information
    3. Lists all indexes
    4. Prints everything nicely
    
    Use this to verify your setup is working!
    """
    print("=" * 60)
    print("  SPLUNK CONNECTION TEST")
    print("=" * 60)
    print()
    
    # Step 1: Read configuration
    config = get_splunk_config()
    print(f"📋 Configuration:")
    print(f"   Host: {config['host']}")
    print(f"   Port: {config['port']}")
    print(f"   Username: {config['username']}")
    print(f"   Password: {'*' * len(config['password'])}")  # Hide password
    print(f"   Default Index: {config['default_index']}")
    print()
    
    # Step 2: Connect to Splunk
    print("🔌 Connecting to Splunk...")
    service = connect_to_splunk()
    print("✅ Connected successfully!")
    print()
    
    # Step 3: Get server info
    print("📊 Splunk Server Information:")
    
    # Get server info using REST API
    server_info = service.info
    print(f"   Server Name: {server_info.get('serverName', 'Unknown')}")
    print(f"   Version: {server_info.get('version', 'Unknown')}")
    print(f"   Build: {server_info.get('build', 'Unknown')}")
    print(f"   OS Name: {server_info.get('os_name', 'Unknown')}")
    print(f"   OS Version: {server_info.get('os_version', 'Unknown')}")
    print(f"   CPU Architecture: {server_info.get('cpu_arch', 'Unknown')}")
    print(f"   License State: {server_info.get('licenseState', 'Unknown')}")
    print()
    
    # Step 4: List all indexes
    print("📁 Splunk Indexes:")
    indexes = service.indexes
    index_count = 0
    for index in indexes:
        # Skip internal indexes that start with _ (except _internal)
        index_name = index.name
        total_events = index["totalEventCount"]
        print(f"   → {index_name}: {total_events} events")
        index_count += 1
    
    print(f"\n   Total indexes: {index_count}")
    print()
    
    # Step 5: Check if our custom indexes exist
    print("🔍 Checking project indexes:")
    security_exists = config["default_index"] in [idx.name for idx in indexes]
    test_exists = config["test_index"] in [idx.name for idx in indexes]
    
    print(f"   'security' index: {'✅ EXISTS' if security_exists else '❌ NOT FOUND'}")
    print(f"   'mcp_test' index: {'✅ EXISTS' if test_exists else '❌ NOT FOUND'}")
    print()
    
    # Final status
    print("=" * 60)
    if security_exists and test_exists:
        print("  🎉 ALL CHECKS PASSED! Splunk connection is PERFECT!")
    else:
        print("  ⚠️  Connection works but some indexes are missing.")
        print("  Create them in Splunk: Settings → Indexes → New Index")
    print("=" * 60)
    print()
    
    return service


# ============================================================
# This block runs ONLY when you execute this file directly
# It does NOT run when other files import this module
# ============================================================
if __name__ == "__main__":
    test_connection()