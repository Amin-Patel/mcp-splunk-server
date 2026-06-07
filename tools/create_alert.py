"""
============================================================
TOOL 4: splunk_create_alert
============================================================
Project  : MCP Server for Splunk
Author   : Sayyed Abuzar
Research : Amin
Layer    : 1 - Core Retrieval / Creation
Status   : PRODUCTION v1.0
============================================================
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from splunk_config import connect_to_splunk
from tools.alert_templates import (
    get_template,
    list_template_names,
    get_templates_summary,
)

ALERT_PREFIX = "MCP_"

SEVERITY_MAP = {
    "INFO":     "1",
    "LOW":      "2",
    "MEDIUM":   "3",
    "HIGH":     "4",
    "CRITICAL": "5",
    "FATAL":    "6",
}


def create_splunk_alert(
    alert_name,
    spl_query,
    severity="MEDIUM",
    cron_schedule="*/15 * * * *",
    description="",
    threshold=0,
):
    """
    Create a new Splunk alert using a custom SPL query.

    CRITICAL AI INSTRUCTION:
    - alert_name: short, no spaces (underscores/hyphens OK)
    - spl_query: valid SPL query string
    - severity: INFO / LOW / MEDIUM / HIGH / CRITICAL / FATAL
    - cron_schedule: standard cron format
    - threshold: alert fires when result count > this number
    - For common threats use create_alert_from_template() instead
    """

    # STEP 1: VALIDATE
    try:
        severity_upper = severity.upper()
        if severity_upper not in SEVERITY_MAP:
            return json.dumps({
                "status":  "Error",
                "message": "Invalid severity '{}'. Choose from: {}".format(
                    severity, list(SEVERITY_MAP.keys())
                ),
            })

        clean_name = alert_name.replace("_", "").replace("-", "")
        if not alert_name or not clean_name.isalnum():
            return json.dumps({
                "status":  "Error",
                "message": "alert_name must only contain letters, numbers, underscores, or hyphens",
            })

        full_name = (
            alert_name
            if alert_name.startswith(ALERT_PREFIX)
            else "{}{}".format(ALERT_PREFIX, alert_name)
        )

        if not spl_query or not spl_query.strip():
            return json.dumps({
                "status":  "Error",
                "message": "spl_query cannot be empty",
            })

        q = spl_query.strip()
        if not q.startswith("|") and not q.lower().startswith("search"):
            spl_query = "search {}".format(q)

    except Exception as e:
        return json.dumps({"status": "Error", "message": "Validation failed: {}".format(str(e))})

    # STEP 2: CONNECT
    try:
        service = connect_to_splunk()
    except Exception as e:
        return json.dumps({"status": "Error", "message": "Splunk connection failed: {}".format(str(e))})

    # STEP 3: DUPLICATE CHECK
    try:
        existing = [s.name for s in service.saved_searches]
        if full_name in existing:
            return json.dumps({
                "status":  "Error",
                "message": "Alert '{}' already exists. Choose a different name or delete it first.".format(full_name),
            })
    except Exception as e:
        return json.dumps({"status": "Error", "message": "Duplicate check failed: {}".format(str(e))})

    # STEP 4: CREATE
    try:
        new_alert = service.saved_searches.create(
            name=full_name,
            search=spl_query,
            **{
                "is_scheduled":     "1",
                "cron_schedule":    cron_schedule,
                "alert_type":       "number of events",
                "alert_comparator": "greater than",
                "alert_threshold":  str(threshold),
                "alert.severity":   SEVERITY_MAP[severity_upper],
                "description":      description or "MCP-created alert: {}".format(alert_name),
                "actions":          "logevent",
            },
        )

        return json.dumps(
            {
                "status":  "Success",
                "message": "Alert '{}' created successfully".format(full_name),
                "alert_details": {
                    "name":          new_alert.name,
                    "search_preview": spl_query[:120] + ("..." if len(spl_query) > 120 else ""),
                    "severity":      severity_upper,
                    "cron_schedule": cron_schedule,
                    "threshold":     threshold,
                    "scheduled":     True,
                },
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"status": "Error", "message": "Alert creation failed: {}".format(str(e))})


def create_alert_from_template(template_key, custom_name=""):
    """
    Create a Splunk alert from a pre-built security template.

    CRITICAL AI INSTRUCTION:
    Available template keys:
      brute_force      - Brute force login detection (HIGH)
      port_scan        - Port scanning detection (MEDIUM)
      dns_anomaly      - DNS exfiltration detection (MEDIUM)
      http_error_spike - HTTP 5xx error spike (LOW)
      suspicious_login - Multi-country user login (HIGH)

    Call list_alert_templates() first if unsure which to use.
    """
    template = get_template(template_key)

    if not template:
        return json.dumps({
            "status":             "Error",
            "message":            "Template '{}' not found.".format(template_key),
            "available_templates": list_template_names(),
        })

    chosen_name = custom_name if custom_name else template["name"]

    return create_splunk_alert(
        alert_name=chosen_name,
        spl_query=template["spl_query"],
        severity=template["severity"],
        cron_schedule=template["cron_schedule"],
        description=template["description"],
        threshold=template["threshold"],
    )


def list_alert_templates():
    """
    Return all available pre-built alert templates.
    Call this before create_alert_from_template() to see options.
    """
    summary = get_templates_summary()
    return json.dumps(
        {
            "status":          "Success",
            "total_templates": len(summary),
            "templates":       summary,
        },
        indent=2,
    )


def delete_splunk_alert(alert_name):
    """
    Delete a Splunk alert by name (cleanup utility).
    MCP_ prefix is optional - will be added automatically.
    """
    full_name = (
        alert_name
        if alert_name.startswith(ALERT_PREFIX)
        else "{}{}".format(ALERT_PREFIX, alert_name)
    )

    try:
        service = connect_to_splunk()
        existing = [s.name for s in service.saved_searches]

        if full_name not in existing:
            return json.dumps({
                "status":  "Error",
                "message": "Alert '{}' not found in Splunk".format(full_name),
            })

        service.saved_searches.delete(full_name)

        return json.dumps({
            "status":  "Success",
            "message": "Alert '{}' deleted successfully".format(full_name),
        })

    except Exception as e:
        return json.dumps({"status": "Error", "message": "Deletion failed: {}".format(str(e))})


if __name__ == "__main__":

    if not os.getenv("SPLUNK_USERNAME"):
        os.environ["SPLUNK_USERNAME"] = "YOUR_USERNAME_HERE"
        os.environ["SPLUNK_PASSWORD"] = "YOUR_PASSWORD_HERE"

    print("=" * 60)
    print("TESTING: splunk_create_alert - Production v1.0")
    print("=" * 60)

    print("\n[Test 1] Listing all available templates...")
    print(list_alert_templates())

    print("\n[Test 2] Creating alert from brute_force template...")
    print(create_alert_from_template("brute_force"))

    print("\n[Test 3] Creating custom alert...")
    print(create_splunk_alert(
        alert_name="CustomTest_Demo",
        spl_query="index=botsv3 | stats count",
        severity="LOW",
        cron_schedule="*/30 * * * *",
        description="Standalone test - custom alert",
    ))

    print("\n[Test 4] Testing invalid template key (should return error)...")
    print(create_alert_from_template("this_does_not_exist"))

    print("\n[Test 5] Cleaning up test alerts...")
    print(delete_splunk_alert("BruteForce_FailedLogins"))
    print(delete_splunk_alert("CustomTest_Demo"))

    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)