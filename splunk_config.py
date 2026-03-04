"""
============================================================
SPLUNK CONFIGURATION MODULE
============================================================
Project: MCP Server for Splunk
Author: Sayyed Abuzar (Team Lead)
Purpose: Handle Splunk connection settings and create
         a reusable connection to Splunk.
============================================================
"""

import os
import sys
import splunklib.client as client
import urllib3

# Suppress SSL warnings (Splunk uses self-signed certificate locally)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Try to load .env for local testing, but don't crash if it's missing 
# because Claude Desktop passes these variables directly!
try:
    from dotenv import load_dotenv
    ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(ENV_PATH):
        load_dotenv(ENV_PATH)
except ImportError:
    pass

def get_splunk_config():
    """
    Read Splunk configuration from Environment Variables.
    (These are provided either by the .env file locally, or by Claude Desktop directly).
    """
    config = {
        "host": os.getenv("SPLUNK_HOST", "localhost"),
        "port": int(os.getenv("SPLUNK_PORT", 8089)),
        "username": os.getenv("SPLUNK_USERNAME", "admin"),
        # Get password from environment (which Claude sets via claude_desktop_config.json)
        "password": os.getenv("SPLUNK_PASSWORD", ""),
        "web_port": int(os.getenv("SPLUNK_WEB_PORT", 8000)),
        "default_index": os.getenv("SPLUNK_DEFAULT_INDEX", "security"),
        "test_index": os.getenv("SPLUNK_TEST_INDEX", "mcp_test"),
        "verify_ssl": os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true",
    }
    
    if not config["password"]:
        raise ValueError("SPLUNK_PASSWORD is empty. Ensure it is set in claude_desktop_config.json or .env")
    
    return config

def connect_to_splunk():
    """
    Create and return an authenticated connection to Splunk.
    """
    config = get_splunk_config()
    try:
        service = client.connect(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            autologin=True
        )
        return service
    except Exception as e:
        raise ConnectionError(f"Failed to connect to Splunk: {str(e)}")