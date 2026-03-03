"""
Alert Fetcher Module for MCP-Splunk
====================================
Captain: Sayyed Abuzar
Created: Week 2, Day 3
Purpose: Fetch alerts and saved searches from Splunk via REST API

This module will be used by the splunk_get_alerts MCP tool in Week 3.
It connects to Splunk, retrieves saved searches/alerts, and formats
them for the LLM to understand.
"""

import splunklib.client as client
import splunklib.results as results
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

# Import our connection config
from splunk_config import get_splunk_config


# ============================================================
# DATA CLASSES
# ============================================================

class AlertSeverity(Enum):
    """Severity levels for alerts"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AlertResult:
    """
    Represents a single alert/saved search result.
    
    Attributes:
        name: Name of the saved search/alert
        description: What this alert detects
        search_query: The SPL query
        severity: Alert severity level
        last_run: When the search was last executed
        result_count: Number of results from last run
        is_scheduled: Whether this is a scheduled alert
        cron_schedule: The schedule (if scheduled)
        actions: Actions configured (email, webhook, etc.)
    """
    name: str
    description: str
    search_query: str
    severity: str
    last_run: Optional[str]
    result_count: int
    is_scheduled: bool
    cron_schedule: Optional[str]
    actions: List[str]


# ============================================================
# SPLUNK CONNECTION
# ============================================================

def connect_to_splunk() -> client.Service:
    """
    Establish connection to Splunk server.
    
    Returns:
        Splunk service object
        
    Raises:
        ConnectionError: If connection fails
    """
    config = get_splunk_config()
    
    try:
        service = client.connect(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            scheme=config.get("scheme", "https")
        )
        return service
    except Exception as e:
        raise ConnectionError(f"Failed to connect to Splunk: {str(e)}")


# ============================================================
# ALERT FETCHING FUNCTIONS
# ============================================================

def get_all_saved_searches(service: client.Service) -> List[Dict]:
    """
    Get all saved searches from Splunk.
    
    Args:
        service: Connected Splunk service
        
    Returns:
        List of saved search dictionaries
    """
    saved_searches = []
    
    for saved_search in service.saved_searches:
        try:
            ss_content = saved_search.content
            
            saved_searches.append({
                "name": saved_search.name,
                "description": ss_content.get("description", "No description"),
                "search": ss_content.get("search", ""),
                "is_scheduled": ss_content.get("is_scheduled", "0") == "1",
                "cron_schedule": ss_content.get("cron_schedule", None),
                "disabled": ss_content.get("disabled", "0") == "1",
                "actions": ss_content.get("actions", "").split(",") if ss_content.get("actions") else [],
                "alert_type": ss_content.get("alert_type", ""),
                "alert_threshold": ss_content.get("alert_threshold", ""),
            })
        except Exception as e:
            print(f"Warning: Could not process saved search '{saved_search.name}': {e}")
            continue
    
    return saved_searches


def get_mcp_alerts(service: client.Service) -> List[Dict]:
    """
    Get only MCP-related saved searches (those starting with 'MCP_').
    
    Args:
        service: Connected Splunk service
        
    Returns:
        List of MCP alert dictionaries
    """
    all_searches = get_all_saved_searches(service)
    mcp_alerts = [ss for ss in all_searches if ss["name"].startswith("MCP_")]
    return mcp_alerts


def get_alerts_by_severity(service: client.Service, severity: str) -> List[Dict]:
    """
    Get alerts filtered by severity level.
    
    Note: Severity is determined by naming convention:
    - MCP_CRITICAL_* = critical
    - MCP_HIGH_* = high
    - MCP_MEDIUM_* = medium
    - MCP_LOW_* = low
    
    Or by description containing [CRITICAL], [HIGH], etc.
    
    Args:
        service: Connected Splunk service
        severity: Severity level to filter (critical, high, medium, low, all)
        
    Returns:
        List of matching alert dictionaries
    """
    mcp_alerts = get_mcp_alerts(service)
    
    if severity.lower() == "all":
        return mcp_alerts
    
    filtered = []
    severity_upper = severity.upper()
    
    for alert in mcp_alerts:
        # Check naming convention
        if f"_{severity_upper}_" in alert["name"].upper():
            filtered.append(alert)
        # Check description
        elif f"[{severity_upper}]" in alert.get("description", "").upper():
            filtered.append(alert)
        # Check for severity keywords in name
        elif severity_upper in alert["name"].upper():
            filtered.append(alert)
    
    return filtered


def run_saved_search(service: client.Service, search_name: str, 
                      earliest: str = "-24h", latest: str = "now") -> List[Dict]:
    """
    Execute a saved search and return results.
    
    Args:
        service: Connected Splunk service
        search_name: Name of the saved search to run
        earliest: Start time for the search
        latest: End time for the search
        
    Returns:
        List of result dictionaries
    """
    try:
        # Get the saved search
        saved_search = service.saved_searches[search_name]
        
        # Dispatch the search (run it)
        job = saved_search.dispatch(
            **{
                "dispatch.earliest_time": earliest,
                "dispatch.latest_time": latest
            }
        )
        
        # Wait for the job to complete
        while not job.is_done():
            import time
            time.sleep(0.5)
        
        # Get results
        result_list = []
        for result in results.JSONResultsReader(job.results(output_mode="json")):
            if isinstance(result, dict):
                result_list.append(result)
        
        return result_list
        
    except KeyError:
        raise ValueError(f"Saved search '{search_name}' not found")
    except Exception as e:
        raise RuntimeError(f"Error running saved search: {str(e)}")


def get_triggered_alerts(service: client.Service, max_count: int = 50) -> List[Dict]:
    """
    Get recently triggered alerts from Splunk.
    
    Args:
        service: Connected Splunk service
        max_count: Maximum number of alerts to retrieve
        
    Returns:
        List of triggered alert dictionaries
    """
    triggered = []
    
    try:
        # Access the fired alerts endpoint
        fired_alerts = service.fired_alerts
        
        count = 0
        for alert in fired_alerts:
            if count >= max_count:
                break
                
            try:
                triggered.append({
                    "name": alert.name,
                    "trigger_time": alert.content.get("trigger_time", "Unknown"),
                    "severity": alert.content.get("severity", "unknown"),
                    "triggered_alerts": alert.content.get("triggered_alerts", 0),
                })
                count += 1
            except Exception as e:
                print(f"Warning: Could not process fired alert: {e}")
                continue
                
    except Exception as e:
        print(f"Note: Could not access fired alerts: {e}")
        print("This is normal if no alerts have been triggered yet.")
    
    return triggered


# ============================================================
# FORMATTED OUTPUT FUNCTIONS
# ============================================================

def format_alerts_for_llm(alerts: List[Dict]) -> str:
    """
    Format alerts into a string that's easy for an LLM to understand.
    
    Args:
        alerts: List of alert dictionaries
        
    Returns:
        Formatted string for LLM consumption
    """
    if not alerts:
        return "No alerts found matching the criteria."
    
    output = []
    output.append(f"Found {len(alerts)} alert(s):\n")
    output.append("=" * 60)
    
    for i, alert in enumerate(alerts, 1):
        output.append(f"\n📋 Alert {i}: {alert['name']}")
        output.append(f"   Description: {alert.get('description', 'No description')}")
        output.append(f"   Scheduled: {'Yes' if alert.get('is_scheduled') else 'No'}")
        
        if alert.get('cron_schedule'):
            output.append(f"   Schedule: {alert['cron_schedule']}")
        
        if alert.get('actions'):
            output.append(f"   Actions: {', '.join(alert['actions'])}")
        
        output.append(f"   Status: {'❌ Disabled' if alert.get('disabled') else '✅ Enabled'}")
        output.append("-" * 40)
    
    return "\n".join(output)


def generate_alert_summary(service: client.Service) -> Dict:
    """
    Generate an executive summary of all MCP alerts.
    
    Args:
        service: Connected Splunk service
        
    Returns:
        Summary dictionary with statistics
    """
    mcp_alerts = get_mcp_alerts(service)
    
    summary = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_mcp_alerts": len(mcp_alerts),
        "enabled_alerts": len([a for a in mcp_alerts if not a.get("disabled")]),
        "disabled_alerts": len([a for a in mcp_alerts if a.get("disabled")]),
        "scheduled_alerts": len([a for a in mcp_alerts if a.get("is_scheduled")]),
        "alert_names": [a["name"] for a in mcp_alerts],
    }
    
    return summary


def print_alert_dashboard():
    """Print a formatted dashboard of all MCP alerts."""
    
    print("\n" + "=" * 70)
    print("🔔 MCP-SPLUNK ALERT DASHBOARD")
    print(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    try:
        # Connect to Splunk
        print("\n📡 Connecting to Splunk...")
        service = connect_to_splunk()
        print("✅ Connected successfully!")
        
        # Get MCP alerts
        mcp_alerts = get_mcp_alerts(service)
        
        if not mcp_alerts:
            print("\n⚠️  No MCP alerts found!")
            print("   Yahya needs to create saved searches starting with 'MCP_'")
            print("   Example: MCP_Detect_XSS, MCP_Detect_SQLi, etc.")
            
            # Show all saved searches as reference
            print("\n📋 All saved searches in Splunk:")
            all_searches = get_all_saved_searches(service)
            for ss in all_searches[:10]:  # Show first 10
                print(f"   → {ss['name']}")
            if len(all_searches) > 10:
                print(f"   ... and {len(all_searches) - 10} more")
        else:
            print(f"\n✅ Found {len(mcp_alerts)} MCP alert(s):")
            print("-" * 70)
            
            for alert in mcp_alerts:
                status = "✅ Enabled" if not alert.get("disabled") else "❌ Disabled"
                scheduled = "⏰ Scheduled" if alert.get("is_scheduled") else "📋 Manual"
                
                print(f"\n📋 {alert['name']}")
                print(f"   Status: {status} | {scheduled}")
                print(f"   Description: {alert.get('description', 'No description')[:50]}...")
                
                if alert.get("cron_schedule"):
                    print(f"   Schedule: {alert['cron_schedule']}")
        
        # Get triggered alerts
        print("\n" + "-" * 70)
        print("🚨 RECENTLY TRIGGERED ALERTS:")
        print("-" * 70)
        
        triggered = get_triggered_alerts(service)
        if triggered:
            for alert in triggered[:5]:
                print(f"   ⚠️  {alert['name']} - Triggered at {alert.get('trigger_time', 'Unknown')}")
        else:
            print("   No recently triggered alerts (this is normal for new setups)")
        
        # Summary
        summary = generate_alert_summary(service)
        print("\n" + "=" * 70)
        print("📊 SUMMARY")
        print("=" * 70)
        print(f"   Total MCP Alerts: {summary['total_mcp_alerts']}")
        print(f"   Enabled: {summary['enabled_alerts']}")
        print(f"   Disabled: {summary['disabled_alerts']}")
        print(f"   Scheduled: {summary['scheduled_alerts']}")
        
    except ConnectionError as e:
        print(f"\n❌ Connection Error: {e}")
        print("   Make sure Splunk is running and credentials are correct.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("✅ Alert Dashboard Complete!")
    print("=" * 70)


# ============================================================
# MAIN — TEST THE MODULE
# ============================================================

if __name__ == "__main__":
    print_alert_dashboard()