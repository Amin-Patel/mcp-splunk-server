"""
============================================================
MCP SERVER FOR SPLUNK (Phase 1 POC)
============================================================
Project: Integration of MCP with Splunk
Author: Sayyed Abuzar (Team Lead)
Purpose: The core MCP Server that exposes our Splunk backend
         (built in Week 2) to Claude Desktop via MCP Tools.
============================================================
"""

import json
from mcp.server.fastmcp import FastMCP
import splunklib.results as results
import time

# Import your excellent backend modules!
from splunk_config import connect_to_splunk

# Initialize the FastMCP Server
# This creates the server object that handles all JSON-RPC communication
mcp = FastMCP("Splunk-Security-Brain")

# ==========================================================
# TOOL 1: SPLUNK HEALTH CHECK
# ==========================================================
@mcp.tool()
def splunk_health_check() -> str:
    """
    Check the health, version, and status of the Splunk SIEM server.
    Use this tool to verify if Splunk is reachable, get its version, 
    and see how many indexes are active.
    """
    try:
        # We use the function you already wrote!
        service = connect_to_splunk()
        info = service.info
        
        # Format the data nicely for the LLM
        health_data = {
            "status": "Healthy & Connected",
            "server_name": info.get("serverName", "Unknown"),
            "splunk_version": info.get("version", "Unknown"),
            "os": info.get("os_name", "Unknown"),
            "active_indexes": len(service.indexes)
        }
        
        # MCP tools must return strings (usually JSON strings)
        return json.dumps(health_data, indent=2)
    
    except Exception as e:
        return json.dumps({"status": "Error", "message": str(e)})

# ==========================================================
# TOOL 2: SPLUNK SEARCH
# ==========================================================
@mcp.tool()
def splunk_search(query: str, earliest_time: str = "0") -> str:
    """
    Execute an SPL (Search Processing Language) query against the Splunk SIEM.
    Use this to hunt for threats, find logs, investigate IPs, or look for anomalies.
    
    Args:
        query: The SPL query string (e.g., 'index=botsv3 sourcetype=stream:http | head 10').
        earliest_time: The time modifier. Default is "0" (all time) for the BOTS v3 dataset.
    """
    try:
        service = connect_to_splunk()
        
        # Ensure the query starts with "search " (You discovered this fix in Week 2!)
        if not query.strip().startswith("|") and not query.strip().startswith("search"):
            query = f"search {query}"
            
        search_params = {
            "earliest_time": earliest_time,
            "latest_time": "now",
            "search_mode": "normal",
            "count": 0 # Get all results
        }
        
        # Create and run the job
        job = service.jobs.create(query, **search_params)
        
        # Wait for the job to finish
        while not job.is_done():
            time.sleep(0.5)
            
        # Parse results
        result_list = []
        reader = results.JSONResultsReader(job.results(output_mode="json"))
        
        for item in reader:
            if isinstance(item, dict):
                # Clean up internal splunk fields to save LLM context window space
                clean_item = {k: v for k, v in item.items() if not k.startswith('_') or k == '_time'}
                result_list.append(clean_item)
                
        job.cancel()
        
        if not result_list:
            return json.dumps({"status": "Success", "message": "Query completed but returned 0 results."})
            
        # Return as formatted JSON string for Claude to read (Limit to top 20 to prevent context overflow)
        return json.dumps(result_list[:20], indent=2)
        
    except Exception as e:
        return json.dumps({"status": "Error", "message": f"Error executing SPL query: {str(e)}"})
# ==========================================================
# MAIN EXECUTION
# ==========================================================
if __name__ == "__main__":
    # This runs the server using standard input/output
    # which is exactly how Claude Desktop will talk to it!
    print("Starting Splunk MCP Server...", flush=True)
    mcp.run(transport="stdio")