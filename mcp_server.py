import sys
import os
import traceback

# ==========================================================
# THE WIRETAP (Crash Logger)
# ==========================================================
LOG_FILE = r"C:\MCP_Project\crash_log.txt"
with open(LOG_FILE, "a", encoding="utf-8") as f:
    f.write("\n" + "="*40 + "\n")
    f.write("1. Server boot sequence started...\n")

try:
    # 1. Force UTF-8 Encoding
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    with open(LOG_FILE, "a", encoding="utf-8") as f: f.write("2. UTF-8 forced successfully.\n")

    # 2. Fix Paths
    PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, PROJECT_DIR)
    os.chdir(PROJECT_DIR)
    with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(f"3. Working directory set to {PROJECT_DIR}\n")

    # 3. Import heavy libraries
    import json
    import time
    from mcp.server.fastmcp import FastMCP
    from splunk_config import connect_to_splunk
    import splunklib.results as results
    with open(LOG_FILE, "a", encoding="utf-8") as f: f.write("4. All modules imported successfully.\n")

    # 4. Initialize FastMCP
    mcp = FastMCP("Splunk-Security-Brain")
    with open(LOG_FILE, "a", encoding="utf-8") as f: f.write("5. FastMCP Initialized.\n")

    # ==========================================================
    # TOOL 1: SPLUNK HEALTH CHECK
    # ==========================================================
    @mcp.tool()
    def splunk_health_check() -> str:
        """Check the health, version, and status of the Splunk SIEM server."""
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
            return json.dumps(health_data, indent=2)
        except Exception as e:
            return json.dumps({"status": "Error", "message": str(e)})

    # ==========================================================
    # TOOL 2: SPLUNK SEARCH (Upgraded with Token Optimization)
    # ==========================================================
    @mcp.tool()
    def splunk_search(query: str, earliest_time: str = "0") -> str:
        """
        Execute an SPL (Search Processing Language) query against the Splunk SIEM.
        Use this to hunt for threats, find logs, investigate IPs, or look for anomalies.
    
        CRITICAL AI INSTRUCTION: 
        To save token context, ALWAYS end your query with `| table field1, field2` 
        or use `| stats` to return ONLY the specific fields needed for the investigation.
        Do NOT return raw logs.
    
        Args:
            query: The SPL query string (e.g., 'index=botsv3 sourcetype=stream:http | stats count by src_ip').
            earliest_time: The time modifier. Default is "0" (all time) for the BOTS v3 dataset.
        """
        try:
            service = connect_to_splunk()
        
            if not query.strip().startswith("|") and not query.strip().startswith("search"):
                query = f"search {query}"
            
            search_params = {
                "earliest_time": earliest_time,
                "latest_time": "now",
                "search_mode": "normal",
                "count": 0 
            }
        
            job = service.jobs.create(query, **search_params)
        
            while not job.is_done():
                time.sleep(0.5)
            
            result_list = []
            reader = results.JSONResultsReader(job.results(output_mode="json"))
        
            # THE BACKEND SHIELD: List of useless Splunk metadata fields to strip out
            useless_fields = {
                "host", "index", "linecount", "source", 
                "sourcetype", "splunk_server", "eventtype", "punct"
            }
        
            for item in reader:
                if isinstance(item, dict):
                    clean_item = {}
                    for k, v in item.items():
                        # Remove internal fields (starting with _) EXCEPT for _time
                        if k.startswith('_') and k != '_time':
                            continue
                        # Remove useless metadata to save LLM tokens
                        if k in useless_fields:
                            continue
                    
                        clean_item[k] = v
                
                    # Only append if the dictionary isn't empty
                    if clean_item:
                        result_list.append(clean_item)
                
            job.cancel()
        
            if not result_list:
                return json.dumps({"status": "Success", "message": "Query completed but returned 0 results."})
            
            # Return max 20 rows to prevent LLM memory overflow
            return json.dumps(result_list[:20], indent=2)
        
        except Exception as e:
            return json.dumps({"status": "Error", "message": f"Error executing SPL query: {str(e)}"})

    # ==========================================================
    # TOOL 3: SPLUNK GET ALERTS
    # ==========================================================
    @mcp.tool()
    def splunk_get_alerts(severity: str = "ALL") -> str:
        """Fetch triggered security alerts and saved searches from Splunk."""
        try:
            service = connect_to_splunk()
            saved_searches = service.saved_searches
            alerts_found = []
            for saved_search in saved_searches:
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
                return json.dumps({"status": "Success", "message": f"No alerts found matching severity: {severity}"})
            return json.dumps(alerts_found, indent=2)
        except Exception as e:
            return json.dumps({"status": "Error", "message": str(e)})

    # ==========================================================
    # MAIN EXECUTION
    # ==========================================================
    if __name__ == "__main__":
        with open(LOG_FILE, "a", encoding="utf-8") as f: f.write("6. Entering stdio run loop. Server is ALIVE.\n")
        mcp.run(transport="stdio")

except Exception as e:
    # IF ANYTHING CRASHES, WRITE IT TO THE DIARY!
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\nCRASH DETECTED: {str(e)}\n")
        f.write(traceback.format_exc() + "\n")