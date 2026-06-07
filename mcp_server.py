import sys
import os
import traceback
import json
import time

from fastmcp import FastMCP
from splunk_config import connect_to_splunk
import splunklib.results as results

# ==========================================================
# TOOL #4 IMPORTS — Alert creation functions
# ==========================================================
from tools.create_alert import (
    create_splunk_alert,
    create_alert_from_template,
    list_alert_templates,
    delete_splunk_alert,
)

# ==========================================================
# PATH FIX — Ensures .env is found regardless of where
# Claude Desktop launches this script from
# ==========================================================

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

# ==========================================================
# CRASH LOGGER — Logs all boot and crash events to file
# ==========================================================

LOG_FILE = os.path.join(PROJECT_DIR, "crash_log.txt")


def log(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


log("=" * 40)
log("Server boot sequence started")
log("Working directory: {}".format(PROJECT_DIR))

# ==========================================================
# INITIALIZE MCP SERVER
# ==========================================================

mcp = FastMCP("Splunk-Security-Brain")
log("FastMCP initialized successfully")

# ==========================================================
# TOOL 1: SPLUNK HEALTH CHECK
# ==========================================================

@mcp.tool()
def splunk_health_check():
    """
    Check the health, version, and status of the Splunk SIEM server.
    Use this at the start of every investigation session to confirm
    the SIEM is online and ready.
    """
    try:
        service = connect_to_splunk()
        info = service.info

        health_data = {
            "status": "Healthy & Connected",
            "server_name": info.get("serverName", "Unknown"),
            "splunk_version": info.get("version", "Unknown"),
            "os": info.get("os_name", "Unknown"),
            "active_indexes": len(service.indexes)
        }

        log("splunk_health_check called successfully")
        return json.dumps(health_data, indent=2)

    except Exception as e:
        log("splunk_health_check ERROR: {}".format(str(e)))
        return json.dumps({"status": "Error", "message": str(e)})


# ==========================================================
# TOOL 2: SPLUNK SEARCH (with Token Optimization)
# ==========================================================

@mcp.tool()
def splunk_search(query, earliest_time="0"):
    """
    Execute an SPL (Search Processing Language) query against the Splunk SIEM.
    Use this to hunt for threats, find logs, investigate IPs, or detect anomalies.

    CRITICAL AI INSTRUCTION:
    To save token context, ALWAYS end your query with '| table field1, field2'
    or use '| stats' to return ONLY the specific fields needed.
    Do NOT return raw logs. Be specific about what fields you need.

    Args:
        query: The SPL query string.
               Example: 'index=botsv3 sourcetype=stream:http | stats count by src_ip'
        earliest_time: Time modifier. Default is "0" (all time) for BOTS v3 dataset.
    """
    try:
        service = connect_to_splunk()

        if not query.strip().startswith("|") and not query.strip().lower().startswith("search"):
            query = "search {}".format(query)

        search_params = {
            "earliest_time": earliest_time,
            "latest_time": "now",
            "search_mode": "normal",
            "count": 0
        }

        job = service.jobs.create(query, **search_params)

        while not job.is_done():
            time.sleep(0.5)

        useless_fields = {
            "host", "index", "linecount", "source",
            "sourcetype", "splunk_server", "eventtype", "punct"
        }

        result_list = []
        reader = results.JSONResultsReader(job.results(output_mode="json"))

        for item in reader:
            if isinstance(item, dict):
                clean_item = {}
                for k, v in item.items():
                    if k.startswith("_") and k != "_time":
                        continue
                    if k in useless_fields:
                        continue
                    clean_item[k] = v

                if clean_item:
                    result_list.append(clean_item)

        job.cancel()

        if not result_list:
            return json.dumps({
                "status": "Success",
                "message": "Query completed but returned 0 results. Try adjusting the time range or query."
            })

        log("splunk_search returned {} results (capped at 20)".format(len(result_list)))
        return json.dumps(result_list[:20], indent=2)

    except Exception as e:
        log("splunk_search ERROR: {}".format(str(e)))
        return json.dumps({"status": "Error", "message": "SPL query error: {}".format(str(e))})


# ==========================================================
# TOOL 3: SPLUNK GET ALERTS
# ==========================================================

@mcp.tool()
def splunk_get_alerts(severity="ALL"):
    """
    Fetch triggered security alerts and saved searches from Splunk.
    Filter by severity level if needed.

    Args:
        severity: Filter by severity. Options: CRITICAL, HIGH, MEDIUM, LOW, ALL
                  Default is ALL which returns every alert found.
    """
    try:
        service = connect_to_splunk()
        alerts_found = []

        for saved_search in service.saved_searches:
            if saved_search.name.startswith("MCP_") or saved_search.name.startswith("DETECTED:"):
                jobs = saved_search.history()
                alert_data = {
                    "alert_name": saved_search.name,
                    "description": saved_search.content.get("description", "No description"),
                    "trigger_count": len(jobs),
                    "search_query": saved_search["search"]
                }

                desc_upper = alert_data["description"].upper()
                if severity.upper() != "ALL" and severity.upper() not in desc_upper:
                    continue

                alerts_found.append(alert_data)

        if not alerts_found:
            log("splunk_get_alerts: No alerts found for severity={}".format(severity))
            return json.dumps({
                "status": "Success",
                "message": "No alerts found matching severity: {}".format(severity)
            })

        log("splunk_get_alerts returned {} alerts".format(len(alerts_found)))
        return json.dumps(alerts_found, indent=2)

    except Exception as e:
        log("splunk_get_alerts ERROR: {}".format(str(e)))
        return json.dumps({"status": "Error", "message": str(e)})


# ==========================================================
# TOOL 4A: CREATE ALERT (Custom SPL)
# ==========================================================

@mcp.tool()
def splunk_create_alert(
    alert_name,
    spl_query,
    severity="MEDIUM",
    cron_schedule="*/15 * * * *",
    description="",
    threshold=0,
):
    """
    Create a new Splunk alert using a custom SPL query.
    The alert will run on a schedule and trigger when results exceed the threshold.
    All MCP-created alerts are prefixed with MCP_ for easy identification.

    CRITICAL AI INSTRUCTION:
    - alert_name: short descriptive name, no spaces (use underscores)
    - spl_query: must be a valid SPL search query
    - severity: INFO / LOW / MEDIUM / HIGH / CRITICAL / FATAL
    - cron_schedule: cron format (*/10 * * * * = every 10 minutes)
    - threshold: alert fires when result count is greater than this (default 0)
    - For common security detections, use splunk_create_alert_from_template instead

    Args:
        alert_name: Short name like BruteForce_Detection
        spl_query: SPL query to monitor
        severity: Alert severity level
        cron_schedule: How often to run the search
        description: Human-readable description
        threshold: Trigger when results exceed this count
    """
    log("splunk_create_alert called: {}".format(alert_name))
    result = create_splunk_alert(
        alert_name=alert_name,
        spl_query=spl_query,
        severity=severity,
        cron_schedule=cron_schedule,
        description=description,
        threshold=threshold,
    )
    return result


# ==========================================================
# TOOL 4B: CREATE ALERT FROM TEMPLATE
# ==========================================================

@mcp.tool()
def splunk_create_alert_from_template(template_key, custom_name=""):
    """
    Create a Splunk alert from a pre-built security detection template.
    Templates include optimized SPL queries, severity levels, and schedules.

    CRITICAL AI INSTRUCTION:
    Available template keys (use these exact strings):
      brute_force      - Detects 50+ failed logins from same IP (HIGH)
      port_scan        - Detects IP scanning 20+ ports (MEDIUM)
      dns_anomaly      - Detects DNS tunneling/exfiltration (MEDIUM)
      http_error_spike - Detects 100+ HTTP 5xx errors (LOW)
      suspicious_login - Detects multi-country user logins (HIGH)

    Call splunk_list_alert_templates first to see all available templates.

    Args:
        template_key: Key of the template to deploy (e.g. brute_force)
        custom_name: Optional custom name to override the template default
    """
    log("splunk_create_alert_from_template called: {}".format(template_key))
    result = create_alert_from_template(
        template_key=template_key,
        custom_name=custom_name,
    )
    return result


# ==========================================================
# TOOL 4C: LIST ALERT TEMPLATES
# ==========================================================

@mcp.tool()
def splunk_list_alert_templates():
    """
    List all available pre-built security alert templates.
    Call this BEFORE creating an alert from a template so you
    can see what options are available.

    Returns template keys, names, categories, severity levels,
    and MITRE ATT&CK technique mappings.
    """
    log("splunk_list_alert_templates called")
    result = list_alert_templates()
    return result


# ==========================================================
# TOOL 4D: DELETE ALERT
# ==========================================================

@mcp.tool()
def splunk_delete_alert(alert_name):
    """
    Delete an MCP-created alert from Splunk.
    Useful for cleanup after testing or removing outdated alerts.
    The MCP_ prefix is added automatically if not provided.

    Args:
        alert_name: Name of the alert to delete (MCP_ prefix optional)
    """
    log("splunk_delete_alert called: {}".format(alert_name))
    result = delete_splunk_alert(alert_name=alert_name)
    return result


# ==========================================================
# MAIN EXECUTION
# ==========================================================

if __name__ == "__main__":
    try:
        log("Entering MCP stdio run loop - server is ALIVE")
        print("MCP server starting...", file=sys.stderr)
        mcp.run(transport="stdio")

    except Exception as e:
        log("CRASH DETECTED: {}".format(str(e)))
        log(traceback.format_exc())
        print("MCP crashed: {}".format(e), file=sys.stderr)