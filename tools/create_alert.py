"""
============================================================
TOOL #4: splunk_create_alert
============================================================
Project: MCP Server for Splunk
Author: Sayyed Abuzar (Team Lead)
Layer: 1 (Core Retrieval/Creation)
Status: SKELETON v1 — to be enhanced with Amin's research

Purpose: Allow Claude AI to create Splunk alerts (saved 
         searches with alert conditions) via natural language.

Example usage from Claude:
    User: "Create an alert that triggers when any IP has 
           more than 50 failed logins in 10 minutes"
    
    Claude calls: splunk_create_alert(
        alert_name="BruteForce_Detection",
        spl_query="index=botsv3 fail* | stats count by src_ip | where count > 50",
        severity="HIGH",
        cron_schedule="*/10 * * * *"
    )
    
    Returns: Confirmation that alert was created in Splunk
============================================================
"""

import json
import sys
import os

# Add parent directory to path so we can import splunk_config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from splunk_config import connect_to_splunk


# ============================================================
# ALERT NAMING CONVENTION
# ============================================================
# All alerts created by MCP will be prefixed with "MCP_"
# This makes them easy to:
#   - Identify in Splunk UI
#   - Filter via splunk_get_alerts
#   - Delete in bulk if needed
# ============================================================
ALERT_PREFIX = "MCP_"

# Valid severity levels (Splunk uses numbers: 1-6)
SEVERITY_MAP = {
    "INFO":      "1",
    "LOW":       "2",
    "MEDIUM":    "3",
    "HIGH":      "4",
    "CRITICAL":  "5",
    "FATAL":     "6"
}


def create_splunk_alert(
    alert_name: str,
    spl_query: str,
    severity: str = "MEDIUM",
    cron_schedule: str = "*/15 * * * *",
    description: str = "",
    threshold: int = 0
) -> str:
    """
    Create a new alert (saved search with alert conditions) in Splunk.
    
    CRITICAL AI INSTRUCTION:
    - alert_name should be descriptive but short (e.g. "BruteForce_FailedLogins")
    - spl_query MUST be a valid SPL search
    - cron_schedule format: minute hour day month weekday
      (Example: "*/10 * * * *" = every 10 minutes)
    - severity options: INFO, LOW, MEDIUM, HIGH, CRITICAL, FATAL
    - The alert triggers when search results count > threshold
    
    Args:
        alert_name: Short descriptive name for the alert
        spl_query: The SPL search query to monitor
        severity: One of INFO/LOW/MEDIUM/HIGH/CRITICAL/FATAL
        cron_schedule: Cron expression for how often to check
        description: Optional human-readable description
        threshold: Trigger when result count exceeds this (default 0)
    
    Returns:
        JSON string with creation status and alert details
    """
    
    # ----------------------------------------------------------
    # STEP 1: INPUT VALIDATION
    # ----------------------------------------------------------
    try:
        # Validate severity
        severity_upper = severity.upper()
        if severity_upper not in SEVERITY_MAP:
            return json.dumps({
                "status": "Error",
                "message": f"Invalid severity '{severity}'. Must be one of: {list(SEVERITY_MAP.keys())}"
            })
        
        # Validate alert_name (only allow letters, numbers, underscores, hyphens)
        clean_name = alert_name.replace("_", "").replace("-", "")
        if not alert_name or not clean_name.isalnum():
            return json.dumps({
                "status": "Error",
                "message": "alert_name must contain only letters, numbers, underscores, hyphens"
            })
        
        # Add MCP_ prefix if not present
        if not alert_name.startswith(ALERT_PREFIX):
            full_alert_name = f"{ALERT_PREFIX}{alert_name}"
        else:
            full_alert_name = alert_name
        
        # Validate SPL query is not empty
        if not spl_query or not spl_query.strip():
            return json.dumps({
                "status": "Error",
                "message": "spl_query cannot be empty"
            })
        
        # Auto-prefix with 'search' if needed
        if not spl_query.strip().startswith("|") and not spl_query.strip().lower().startswith("search"):
            spl_query = f"search {spl_query}"
        
    except Exception as e:
        return json.dumps({
            "status": "Error",
            "message": f"Validation failed: {str(e)}"
        })
    
    # ----------------------------------------------------------
    # STEP 2: CONNECT TO SPLUNK
    # ----------------------------------------------------------
    try:
        service = connect_to_splunk()
    except Exception as e:
        return json.dumps({
            "status": "Error",
            "message": f"Failed to connect to Splunk: {str(e)}"
        })
    
    # ----------------------------------------------------------
    # STEP 3: CHECK IF ALERT ALREADY EXISTS
    # ----------------------------------------------------------
    try:
        existing_names = [s.name for s in service.saved_searches]
        if full_alert_name in existing_names:
            return json.dumps({
                "status": "Error",
                "message": f"Alert '{full_alert_name}' already exists. Use a different name or delete the existing one first."
            })
    except Exception as e:
        return json.dumps({
            "status": "Error",
            "message": f"Failed to check existing alerts: {str(e)}"
        })
    
    # ----------------------------------------------------------
    # STEP 4: CREATE THE ALERT
    # ----------------------------------------------------------
    # This is the CONFIRMED working approach (proven via test_create_alert.py)
    # Enterprise license supports all these parameters.
    # ----------------------------------------------------------
    try:
        new_alert = service.saved_searches.create(
            name=full_alert_name,
            search=spl_query,
            **{
                "is_scheduled": "1",
                "cron_schedule": cron_schedule,
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": str(threshold),
                "alert.severity": SEVERITY_MAP[severity_upper],
                "description": description or f"MCP-created alert: {alert_name}",
                "actions": "logevent"
            }
        )
        
        return json.dumps({
            "status": "Success",
            "message": f"Alert '{full_alert_name}' created successfully",
            "alert_details": {
                "name": new_alert.name,
                "search": spl_query[:100] + ("..." if len(spl_query) > 100 else ""),
                "severity": severity_upper,
                "cron_schedule": cron_schedule,
                "threshold": threshold,
                "scheduled": True
            }
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "status": "Error",
            "message": f"Failed to create alert: {str(e)}"
        })


def delete_splunk_alert(alert_name: str) -> str:
    """
    Helper function to delete an alert (useful for testing).
    
    Args:
        alert_name: Name of the alert to delete (with or without MCP_ prefix)
    
    Returns:
        JSON string with deletion status
    """
    # Add prefix if missing
    if not alert_name.startswith(ALERT_PREFIX):
        full_alert_name = f"{ALERT_PREFIX}{alert_name}"
    else:
        full_alert_name = alert_name
    
    try:
        service = connect_to_splunk()
        
        if full_alert_name not in [s.name for s in service.saved_searches]:
            return json.dumps({
                "status": "Error",
                "message": f"Alert '{full_alert_name}' does not exist"
            })
        
        service.saved_searches.delete(full_alert_name)
        
        return json.dumps({
            "status": "Success",
            "message": f"Alert '{full_alert_name}' deleted successfully"
        })
        
    except Exception as e:
        return json.dumps({
            "status": "Error",
            "message": f"Failed to delete alert: {str(e)}"
        })


# ============================================================
# STANDALONE TEST (run directly to test without Claude)
# ============================================================
if __name__ == "__main__":
    # Set credentials for standalone testing
    # (Claude Desktop sets these via env vars normally)
    if not os.getenv("SPLUNK_USERNAME"):
        print("⚠️ Setting test credentials for standalone run...")
        os.environ["SPLUNK_USERNAME"] = "LightDevil"
        os.environ["SPLUNK_PASSWORD"] = "********Az06"
    
    print("=" * 60)
    print("TESTING: splunk_create_alert")
    print("=" * 60)
    
    # Test 1: Create a brute force alert
    print("\n[Test 1] Creating brute force detection alert...")
    result = create_splunk_alert(
        alert_name="SkeletonTest_BruteForce",
        spl_query='index=botsv3 (fail* OR "invalid password") | stats count by src_ip | where count > 50',
        severity="HIGH",
        cron_schedule="*/10 * * * *",
        description="Skeleton test — brute force detection",
        threshold=0
    )
    print(result)
    
    # Test 2: Try to create the same alert again (should fail with "already exists")
    print("\n[Test 2] Creating duplicate alert (should fail)...")
    result = create_splunk_alert(
        alert_name="SkeletonTest_BruteForce",
        spl_query="index=botsv3 | stats count by src_ip",
        severity="HIGH"
    )
    print(result)
    
    # Test 3: Cleanup — delete the test alert
    print("\n[Test 3] Cleaning up test alert...")
    result = delete_splunk_alert("SkeletonTest_BruteForce")
    print(result)
    
    print("\n" + "=" * 60)
    print("TESTING COMPLETE")
    print("=" * 60)