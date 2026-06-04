"""
============================================================
SPLUNK CONFIGURATION MODULE
============================================================
Project: MCP Server for Splunk
Author: Sayyed Abuzar (Team Lead)
Purpose: Handle Splunk connection settings and create
         a reusable connection to Splunk.

Mode: Splunk Enterprise (Dev License)
Auth: Username + Password via environment variables
============================================================
"""

import os
import sys
import splunklib.client as client
import urllib3

# Suppress SSL warnings (Splunk uses self-signed certificate locally)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Try to load .env for local testing
try:
    from dotenv import load_dotenv
    ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(ENV_PATH):
        load_dotenv(ENV_PATH)
except ImportError:
    pass


def get_splunk_config():
    """
    Read Splunk configuration from environment variables.
    These are provided by Claude Desktop via claude_desktop_config.json
    OR via .env file for local testing.
    """
    config = {
        "host": os.getenv("SPLUNK_HOST", "localhost"),
        "port": int(os.getenv("SPLUNK_PORT", 8089)),
        "username": os.getenv("SPLUNK_USERNAME", ""),
        "password": os.getenv("SPLUNK_PASSWORD", ""),
        "web_port": int(os.getenv("SPLUNK_WEB_PORT", 8000)),
        "default_index": os.getenv("SPLUNK_DEFAULT_INDEX", "security"),
        "test_index": os.getenv("SPLUNK_TEST_INDEX", "mcp_test"),
        "verify_ssl": os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true",
    }

    if not config["username"]:
        raise ValueError(
            "SPLUNK_USERNAME is empty. "
            "Set it in claude_desktop_config.json or .env file."
        )

    if not config["password"]:
        raise ValueError(
            "SPLUNK_PASSWORD is empty. "
            "Set it in claude_desktop_config.json or .env file."
        )

    return config


def connect_to_splunk():
    """
    Create and return an authenticated connection to Splunk Enterprise.
    Uses username/password authentication.
    """
    config = get_splunk_config()

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
        raise ConnectionError(
            f"Failed to connect to Splunk Enterprise at "
            f"{config['host']}:{config['port']}. "
            f"Error: {str(e)}"
        )