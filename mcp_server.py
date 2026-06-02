import sys
import os
import traceback
import json
import time

from fastmcp import FastMCP
from splunk_config import connect_to_splunk
import splunklib.results as results

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


def log(msg: str) -> None:
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


log("=" * 40)
log("Server boot sequence started")
log(f"Working directory: {PROJECT_DIR}")

# ==========================================================
# INITIALIZE MCP SERVER
# ==========================================================

mcp = FastMCP("Splunk-Security-Brain")
log("FastMCP initialized successfully")

# ==========================================================
# TOOL 1: SPLUNK HEALTH CHECK
# ==========================================================

@mcp.tool()
def splunk_health_check() -> str:
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
        log(f"splunk_health_check ERROR: {str(e)}")
        return json.dumps({"status": "Error", "message": str(e)})


# ==========================================================
# TOOL 2: SPLUNK SEARCH (with Token Optimization)
# ==========================================================

@mcp.tool()
def splunk_search(query: str, earliest_time: str = "0") -> str:
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

        # Auto-prefix with 'search' if needed
        if not query.strip().startswith("|") and not query.strip().lower().startswith("search"):
            query = f"search {query}"

        search_params = {
            "earliest_time": earliest_time,
            "latest_time": "now",
            "search_mode": "normal",
            "count": 0
        }

        job = service.jobs.create(query, **search_params)

        # Wait for job to complete
        while not job.is_done():
            time.sleep(0.5)

        # THE BACKEND SHIELD — Strip useless metadata fields
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
                    # Remove internal fields (starting with _) EXCEPT _time
                    if k.startswith("_") and k != "_time":
                        continue
                    # Remove useless metadata
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

        # Limit to 20 rows to prevent LLM token overflow
        log(f"splunk_search returned {len(result_list)} results (capped at 20)")
        return json.dumps(result_list[:20], indent=2)

    except Exception as e:
        log(f"splunk_search ERROR: {str(e)}")
        return json.dumps({"status": "Error", "message": f"SPL query error: {str(e)}"})


# ==========================================================
# TOOL 3: SPLUNK GET ALERTS
# ==========================================================

@mcp.tool()
def splunk_get_alerts(severity: str = "ALL") -> str:
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
            log(f"splunk_get_alerts: No alerts found for severity={severity}")
            return json.dumps({
                "status": "Success",
                "message": f"No alerts found matching severity: {severity}"
            })

        log(f"splunk_get_alerts returned {len(alerts_found)} alerts")
        return json.dumps(alerts_found, indent=2)

    except Exception as e:
        log(f"splunk_get_alerts ERROR: {str(e)}")
        return json.dumps({"status": "Error", "message": str(e)})


# ==========================================================
# MAIN EXECUTION
# ==========================================================

if __name__ == "__main__":
    try:
        log("Entering MCP stdio run loop — server is ALIVE")
        print("MCP server starting...", file=sys.stderr)
        mcp.run(transport="stdio")

    except Exception as e:
        log(f"CRASH DETECTED: {str(e)}")
        log(traceback.format_exc())
        print(f"MCP crashed: {e}", file=sys.stderr)