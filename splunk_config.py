"""
============================================================
SPLUNK CONFIGURATION MODULE
============================================================
Project: MCP Server for Splunk
Author: Sayyed Abuzar (Team Lead)
Purpose: Handle Splunk connection settings and create
         a reusable connection to Splunk.

Supports BOTH:
  - Splunk Free Edition (no authentication)
  - Splunk Enterprise / Trial / Dev License (with auth)

Auto-detects which mode to use based on env config.
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
    (These are provided either by the .env file locally, 
     or by Claude Desktop directly via claude_desktop_config.json)
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
        # NEW: Detect Splunk Free Edition mode (no auth required)
        "free_mode": os.getenv("SPLUNK_FREE_MODE", "false").lower() == "true",
    }

    return config


def connect_to_splunk():
    """
    Create and return a connection to Splunk.
    
    Connection strategy:
      1. If SPLUNK_FREE_MODE=true → connect WITHOUT authentication
      2. Otherwise → connect WITH username/password (Enterprise/Trial mode)
      3. If auth mode fails → try free mode as fallback
    
    This ensures the MCP server works regardless of which 
    Splunk license type you're using.
    """
    config = get_splunk_config()

    # ============================================================
    # MODE 1: SPLUNK FREE EDITION (no authentication)
    # ============================================================
    if config["free_mode"]:
        try:
            service = client.connect(
                host=config["host"],
                port=config["port"],
                scheme="https",
                verify=config["verify_ssl"]
            )
            return service
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to Splunk Free Edition: {str(e)}"
            )

    # ============================================================
    # MODE 2: SPLUNK ENTERPRISE / TRIAL / DEV LICENSE (with auth)
    # ============================================================
    if not config["password"]:
        # No password set AND not in free mode → try free mode anyway
        try:
            service = client.connect(
                host=config["host"],
                port=config["port"],
                scheme="https",
                verify=config["verify_ssl"]
            )
            return service
        except Exception as e:
            raise ValueError(
                "SPLUNK_PASSWORD is empty AND Free Mode connection failed. "
                "Set SPLUNK_PASSWORD in claude_desktop_config.json OR "
                "set SPLUNK_FREE_MODE=true for Splunk Free Edition. "
                f"Original error: {str(e)}"
            )

    try:
        service = client.connect(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            scheme="https",
            verify=config["verify_ssl"],
            autologin=True
        )
        return service
    except Exception as e:
        # If auth mode fails, try free mode as last resort
        try:
            service = client.connect(
                host=config["host"],
                port=config["port"],
                scheme="https",
                verify=config["verify_ssl"]
            )
            return service
        except Exception as e2:
            raise ConnectionError(
                f"Failed to connect to Splunk. "
                f"Auth mode error: {str(e)}. "
                f"Free mode fallback also failed: {str(e2)}"
            )