"""
============================================================
ATTACK DETECTION TEST — Running Security Queries from Python
============================================================
Project: MCP Server for Splunk
Author: Sayyed Abuzar (Team Lead)
Purpose: Verify that our Python code can detect real attacks
         in the BOTS v3 dataset. These queries will be used
         by our MCP splunk_search tool in Week 3.

Features:
- Runs 5 attack detection queries against BOTS v3
- Collects top findings from each scan
- Generates a PRIORITY-BASED summary at the end
- Red = URGENT, Yellow = INVESTIGATE, Green = ALL CLEAR
============================================================
"""

import time
from splunk_config import connect_to_splunk
import splunklib.results as results


def run_detection_query(service, query, description, earliest="0"):
    """
    Execute a detection query and return formatted results.
    
    Parameters:
        service: Connected Splunk service object
        query: SPL query string
        description: What this query detects
        earliest: Time range ("0" = all time for BOTS data)
    
    Returns:
        dict: Contains 'results', 'count', 'duration', 'description'
    """
    print(f"\n{'='*60}")
    print(f"  🔍 {description}")
    print(f"{'='*60}")
    print(f"  Query: {query[:80]}...")
    print(f"  ⏳ Executing...")
    
    # Make sure query starts with "search"
    if not query.startswith("|") and not query.startswith("search"):
        query = f"search {query}"
    
    start_time = time.time()
    
    # Create search job
    search_params = {
        "earliest_time": earliest,
        "latest_time": "now",
        "search_mode": "normal",
        "count": 0,
    }
    
    try:
        job = service.jobs.create(query, **search_params)
        
        # Wait for completion
        while not job.is_done():
            time.sleep(0.5)
            print(".", end="", flush=True)
        
        duration = round(time.time() - start_time, 2)
        result_count = int(job["resultCount"])
        print(f"\n  ✅ Completed in {duration}s — {result_count} results")
        
        # Read results
        result_list = []
        reader = results.JSONResultsReader(job.results(output_mode="json"))
        for item in reader:
            if isinstance(item, dict):
                result_list.append(item)
        
        # Clean up
        job.cancel()
        
        # Print results
        if result_list:
            print(f"\n  📊 Top Results:")
            print(f"  {'─'*50}")
            for i, row in enumerate(result_list[:5]):
                parts = []
                for key, value in row.items():
                    if not key.startswith("_"):
                        parts.append(f"{key}={value}")
                print(f"  {i+1}. {' | '.join(parts)}")
        else:
            print(f"  📭 No results found")
        
        return {
            "results": result_list,
            "count": result_count,
            "duration": duration,
            "description": description
        }
    
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
        return {
            "results": [],
            "count": 0,
            "duration": 0,
            "description": description
        }


def assess_severity(attack_type, result_data):
    """
    Assess the severity of each finding based on attack type and results.
    
    Returns:
        dict: Contains 'level', 'icon', 'label', 'summary', 'top_finding'
    
    Severity Levels:
        🔴 CRITICAL  → Immediate action required
        🟠 HIGH      → Investigate within hours
        🟡 MEDIUM    → Review and monitor
        🔵 LOW       → Informational, no immediate action
        🟢 CLEAR     → No threats detected
    """
    result_list = result_data["results"]
    count = result_data["count"]
    
    if attack_type == "brute_force":
        if count == 0:
            return {
                "level": "CLEAR",
                "icon": "🟢",
                "label": "ALL CLEAR",
                "summary": "No failed login attempts detected",
                "top_finding": "None"
            }
        elif count <= 5:
            return {
                "level": "LOW",
                "icon": "🔵",
                "label": "LOW",
                "summary": f"{count} failed login(s) found — normal activity, not a brute force attack",
                "top_finding": _extract_top_finding(result_list, ["Source_Network_Address", "src_ip", "Account_Name", "user"])
            }
        elif count <= 50:
            return {
                "level": "MEDIUM",
                "icon": "🟡",
                "label": "MEDIUM",
                "summary": f"{count} failed logins detected — possible targeted attack, needs review",
                "top_finding": _extract_top_finding(result_list, ["Source_Network_Address", "src_ip", "Account_Name", "user"])
            }
        elif count <= 200:
            return {
                "level": "HIGH",
                "icon": "🟠",
                "label": "HIGH",
                "summary": f"{count} failed logins detected — likely brute force attack in progress!",
                "top_finding": _extract_top_finding(result_list, ["Source_Network_Address", "src_ip", "Account_Name", "user"])
            }
        else:
            return {
                "level": "CRITICAL",
                "icon": "🔴",
                "label": "CRITICAL",
                "summary": f"{count} failed logins detected — ACTIVE brute force attack! Immediate action required!",
                "top_finding": _extract_top_finding(result_list, ["Source_Network_Address", "src_ip", "Account_Name", "user"])
            }
    
    elif attack_type == "dns_anomaly":
        if count == 0:
            return {
                "level": "CLEAR",
                "icon": "🟢",
                "label": "ALL CLEAR",
                "summary": "No suspicious DNS activity detected",
                "top_finding": "None"
            }
        else:
            # Check if any domain is suspiciously long
            has_very_long = False
            longest_domain = ""
            for r in result_list:
                domain = r.get("dns_query", r.get("query", ""))
                length = int(r.get("query_length", 0))
                if length > 60:
                    has_very_long = True
                if len(domain) > len(longest_domain):
                    longest_domain = domain
            
            if has_very_long:
                return {
                    "level": "MEDIUM",
                    "icon": "🟡",
                    "label": "MEDIUM",
                    "summary": f"{count} long DNS queries found — possible DNS tunneling or C2 communication",
                    "top_finding": f"Longest domain: {longest_domain[:60]}..."
                }
            else:
                return {
                    "level": "LOW",
                    "icon": "🔵",
                    "label": "LOW",
                    "summary": f"{count} slightly long DNS queries — likely CDN/cloud services",
                    "top_finding": f"Top domain: {longest_domain[:60]}..."
                }
    
    elif attack_type == "web_attack":
        if count == 0:
            return {
                "level": "CLEAR",
                "icon": "🟢",
                "label": "ALL CLEAR",
                "summary": "No web attack indicators found",
                "top_finding": "None"
            }
        else:
            # Look for high-frequency attackers
            top_ip = ""
            top_count = 0
            for r in result_list:
                c = int(r.get("count", 0))
                if c > top_count:
                    top_count = c
                    top_ip = r.get("src_ip", "Unknown")
            
            if top_count > 100:
                return {
                    "level": "CRITICAL",
                    "icon": "🔴",
                    "label": "CRITICAL",
                    "summary": f"Active web attack detected! {top_ip} generated {top_count} error responses!",
                    "top_finding": f"Attacker IP: {top_ip} | Errors: {top_count}"
                }
            elif top_count > 20:
                return {
                    "level": "HIGH",
                    "icon": "🟠",
                    "label": "HIGH",
                    "summary": f"Web attack activity from {top_ip} — {top_count} suspicious requests",
                    "top_finding": f"Attacker IP: {top_ip} | Errors: {top_count}"
                }
            else:
                return {
                    "level": "MEDIUM",
                    "icon": "🟡",
                    "label": "MEDIUM",
                    "summary": f"Some HTTP errors detected — review for potential web attacks",
                    "top_finding": f"Top IP: {top_ip} | Errors: {top_count}"
                }
    
    elif attack_type == "port_scan":
        if count == 0:
            return {
                "level": "CLEAR",
                "icon": "🟢",
                "label": "ALL CLEAR",
                "summary": "No port scanning activity detected",
                "top_finding": "None"
            }
        else:
            # Find the most aggressive scanner
            top_ip = ""
            top_ports = 0
            for r in result_list:
                ports = int(r.get("unique_ports", 0))
                if ports > top_ports:
                    top_ports = ports
                    top_ip = r.get("src_ip", "Unknown")
            
            if top_ports > 100:
                return {
                    "level": "CRITICAL",
                    "icon": "🔴",
                    "label": "CRITICAL",
                    "summary": f"Aggressive port scan! {top_ip} scanned {top_ports} ports! Immediate investigation needed!",
                    "top_finding": f"Scanner IP: {top_ip} | Ports: {top_ports}"
                }
            elif top_ports > 30:
                return {
                    "level": "HIGH",
                    "icon": "🟠",
                    "label": "HIGH",
                    "summary": f"Port scanning detected from {top_ip} — {top_ports} unique ports targeted",
                    "top_finding": f"Scanner IP: {top_ip} | Ports: {top_ports}"
                }
            elif top_ports > 15:
                return {
                    "level": "MEDIUM",
                    "icon": "🟡",
                    "label": "MEDIUM",
                    "summary": f"Moderate port activity from {top_ip} — {top_ports} ports",
                    "top_finding": f"Source IP: {top_ip} | Ports: {top_ports}"
                }
            else:
                return {
                    "level": "LOW",
                    "icon": "🔵",
                    "label": "LOW",
                    "summary": f"Minor port activity detected — likely normal traffic",
                    "top_finding": f"Top IP: {top_ip} | Ports: {top_ports}"
                }
    
    elif attack_type == "data_exfil":
        if count == 0:
            return {
                "level": "CLEAR",
                "icon": "🟢",
                "label": "ALL CLEAR",
                "summary": "No unusual outbound data transfers detected",
                "top_finding": "None"
            }
        else:
            # Find the biggest data sender
            top_ip = ""
            top_mb = 0
            for r in result_list:
                mb = float(r.get("MB_out", 0))
                if mb > top_mb:
                    top_mb = mb
                    top_ip = r.get("src_ip", "Unknown")
            
            if top_mb > 500:
                return {
                    "level": "CRITICAL",
                    "icon": "🔴",
                    "label": "CRITICAL",
                    "summary": f"MASSIVE data exfiltration! {top_ip} sent {top_mb} MB outbound! Immediate action!",
                    "top_finding": f"Exfil IP: {top_ip} | Data Out: {top_mb} MB"
                }
            elif top_mb > 100:
                return {
                    "level": "HIGH",
                    "icon": "🟠",
                    "label": "HIGH",
                    "summary": f"Large outbound transfer from {top_ip} — {top_mb} MB sent out of network",
                    "top_finding": f"Source IP: {top_ip} | Data Out: {top_mb} MB"
                }
            elif top_mb > 50:
                return {
                    "level": "MEDIUM",
                    "icon": "🟡",
                    "label": "MEDIUM",
                    "summary": f"Moderate outbound data from {top_ip} — {top_mb} MB",
                    "top_finding": f"Source IP: {top_ip} | Data Out: {top_mb} MB"
                }
            else:
                return {
                    "level": "LOW",
                    "icon": "🔵",
                    "label": "LOW",
                    "summary": f"Normal outbound traffic levels",
                    "top_finding": f"Top IP: {top_ip} | Data Out: {top_mb} MB"
                }
    
    # Default fallback
    return {
        "level": "CLEAR",
        "icon": "🟢",
        "label": "ALL CLEAR",
        "summary": "No issues detected",
        "top_finding": "None"
    }


def _extract_top_finding(result_list, possible_fields):
    """
    Extract the top finding from results, trying multiple field names.
    """
    if not result_list:
        return "None"
    
    top = result_list[0]
    parts = []
    for field in possible_fields:
        if field in top:
            parts.append(f"{field}: {top[field]}")
    
    count = top.get("count", "N/A")
    parts.append(f"count: {count}")
    
    return " | ".join(parts) if parts else "Data available but fields not matched"


def print_executive_summary(all_assessments):
    """
    Print a beautiful executive summary with priority-based color coding.
    
    🔴 CRITICAL  → Immediate action required — STOP everything and investigate
    🟠 HIGH      → Investigate within hours — serious threat
    🟡 MEDIUM    → Review and monitor — potential threat
    🔵 LOW       → Informational — no immediate concern
    🟢 CLEAR     → All good — no threats detected
    """
    print(f"\n\n")
    print(f"{'╔' + '═'*68 + '╗'}")
    print(f"{'║'} {'🛡️  SECURITY ASSESSMENT — EXECUTIVE SUMMARY':^66} {'║'}")
    print(f"{'╠' + '═'*68 + '╣'}")
    
    # Count severity levels
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAR": 0}
    urgent_items = []
    non_urgent_items = []
    clear_items = []
    
    for attack_name, assessment in all_assessments.items():
        level = assessment["level"]
        severity_counts[level] += 1
        
        if level in ["CRITICAL", "HIGH"]:
            urgent_items.append((attack_name, assessment))
        elif level in ["MEDIUM", "LOW"]:
            non_urgent_items.append((attack_name, assessment))
        else:
            clear_items.append((attack_name, assessment))
    
    # Overall status
    if severity_counts["CRITICAL"] > 0:
        overall_icon = "🔴"
        overall_status = "CRITICAL — IMMEDIATE ACTION REQUIRED"
    elif severity_counts["HIGH"] > 0:
        overall_icon = "🟠"
        overall_status = "HIGH ALERT — INVESTIGATION NEEDED"
    elif severity_counts["MEDIUM"] > 0:
        overall_icon = "🟡"
        overall_status = "ELEVATED — MONITORING RECOMMENDED"
    elif severity_counts["LOW"] > 0:
        overall_icon = "🔵"
        overall_status = "LOW RISK — INFORMATIONAL ITEMS NOTED"
    else:
        overall_icon = "🟢"
        overall_status = "ALL CLEAR — NO THREATS DETECTED"
    
    print(f"{'║'}{'':68}{'║'}")
    print(f"{'║'}  Overall Status: {overall_icon} {overall_status:<47}{'║'}")
    print(f"{'║'}{'':68}{'║'}")
    
    # Print severity distribution
    print(f"{'║'}  Severity Distribution:{'':44}{'║'}")
    print(f"{'║'}  🔴 Critical: {severity_counts['CRITICAL']}  🟠 High: {severity_counts['HIGH']}  🟡 Medium: {severity_counts['MEDIUM']}  🔵 Low: {severity_counts['LOW']}  🟢 Clear: {severity_counts['CLEAR']:<4}{'║'}")
    print(f"{'║'}{'':68}{'║'}")
    print(f"{'╠' + '═'*68 + '╣'}")
    
    # URGENT ITEMS (Red/Orange section)
    if urgent_items:
        print(f"{'║'}{'':68}{'║'}")
        print(f"{'║'}  {'⚠️  REQUIRES IMMEDIATE ATTENTION:':<66}{'║'}")
        print(f"{'║'}  {'─'*64}  {'║'}")
        for attack_name, assessment in urgent_items:
            icon = assessment["icon"]
            label = assessment["label"]
            print(f"{'║'}{'':68}{'║'}")
            print(f"{'║'}  {icon} [{label}] {attack_name:<53}{'║'}")
            
            # Word wrap the summary
            summary = assessment["summary"]
            while len(summary) > 60:
                print(f"{'║'}    {summary[:60]:<64}{'║'}")
                summary = summary[60:]
            print(f"{'║'}    {summary:<64}{'║'}")
            
            finding = assessment["top_finding"]
            if len(finding) > 60:
                finding = finding[:57] + "..."
            print(f"{'║'}    📌 {finding:<62}{'║'}")
        
        print(f"{'║'}{'':68}{'║'}")
        print(f"{'╠' + '═'*68 + '╣'}")
    
    # NON-URGENT ITEMS (Yellow/Blue section)
    if non_urgent_items:
        print(f"{'║'}{'':68}{'║'}")
        print(f"{'║'}  {'📋  REVIEW WHEN POSSIBLE:':<66}{'║'}")
        print(f"{'║'}  {'─'*64}  {'║'}")
        for attack_name, assessment in non_urgent_items:
            icon = assessment["icon"]
            label = assessment["label"]
            print(f"{'║'}{'':68}{'║'}")
            print(f"{'║'}  {icon} [{label}] {attack_name:<53}{'║'}")
            
            summary = assessment["summary"]
            while len(summary) > 60:
                print(f"{'║'}    {summary[:60]:<64}{'║'}")
                summary = summary[60:]
            print(f"{'║'}    {summary:<64}{'║'}")
            
            finding = assessment["top_finding"]
            if len(finding) > 60:
                finding = finding[:57] + "..."
            print(f"{'║'}    📌 {finding:<62}{'║'}")
        
        print(f"{'║'}{'':68}{'║'}")
        print(f"{'╠' + '═'*68 + '╣'}")
    
    # CLEAR ITEMS (Green section)
    if clear_items:
        print(f"{'║'}{'':68}{'║'}")
        print(f"{'║'}  {'✅  NO ISSUES DETECTED:':<66}{'║'}")
        print(f"{'║'}  {'─'*64}  {'║'}")
        for attack_name, assessment in clear_items:
            print(f"{'║'}  🟢 {attack_name}: {assessment["summary"][:47]:<51}{'║'}")
        print(f"{'║'}{'':68}{'║'}")
    
    # RECOMMENDATIONS
    print(f"{'╠' + '═'*68 + '╣'}")
    print(f"{'║'}{'':68}{'║'}")
    print(f"{'║'}  {'📊  RECOMMENDED ACTIONS:':<66}{'║'}")
    print(f"{'║'}  {'─'*64}  {'║'}")
    
    if severity_counts["CRITICAL"] > 0:
        print(f"{'║'}  1. 🔴 STOP — Investigate critical findings IMMEDIATELY{'':12}{'║'}")
        print(f"{'║'}  2. 🔴 Block attacking IPs at firewall{'':29}{'║'}")
        print(f"{'║'}  3. 🔴 Preserve evidence for forensic analysis{'':21}{'║'}")
        print(f"{'║'}  4. 🟠 Review high-priority items within 1 hour{'':20}{'║'}")
    elif severity_counts["HIGH"] > 0:
        print(f"{'║'}  1. 🟠 Investigate high-priority findings within hours{'':14}{'║'}")
        print(f"{'║'}  2. 🟠 Monitor affected IPs and users closely{'':22}{'║'}")
        print(f"{'║'}  3. 🟡 Review medium items during next shift{'':24}{'║'}")
    elif severity_counts["MEDIUM"] > 0:
        print(f"{'║'}  1. 🟡 Review medium-priority items during this shift{'':14}{'║'}")
        print(f"{'║'}  2. 🔵 Note low-priority items for weekly review{'':19}{'║'}")
    else:
        print(f"{'║'}  ✅ No immediate action required{'':35}{'║'}")
        print(f"{'║'}  ✅ Continue regular monitoring{'':37}{'║'}")
    
    print(f"{'║'}{'':68}{'║'}")
    print(f"{'╠' + '═'*68 + '╣'}")
    print(f"{'║'}{'':68}{'║'}")
    print(f"{'║'}  {'Generated by: MCP-Splunk Security Assessment System':<66}{'║'}")
    print(f"{'║'}  {'Project: MCP Server for Splunk — Phase 1':<66}{'║'}")
    print(f"{'║'}  {'Team Lead: Sayyed Abuzar':<66}{'║'}")
    print(f"{'║'}{'':68}{'║'}")
    print(f"{'╚' + '═'*68 + '╝'}")


def main():
    """
    Run all attack detection queries against BOTS v3 dataset
    and generate a priority-based executive summary.
    """
    print(f"\n{'='*60}")
    print(f"  ATTACK DETECTION SCAN — BOTS v3 Dataset")
    print(f"  MCP-Splunk Project — Week 2")
    print(f"  {'─'*56}")
    print(f"  Scanning 2,083,056 events across 107 sourcetypes...")
    print(f"{'='*60}")
    
    # Connect to Splunk
    print(f"\n🔌 Connecting to Splunk...")
    service = connect_to_splunk()
    print(f"✅ Connected!")
    
    # Store all assessments for the executive summary
    all_assessments = {}
    
    # ================================================
    # DETECTION 1: Brute Force
    # ================================================
    query1 = """index=botsv3 earliest=0 sourcetype="wineventlog:security" EventCode=4625
    | stats count by Source_Network_Address, Account_Name
    | sort - count
    | head 10"""
    
    result1 = run_detection_query(
        service, query1,
        "ATTACK 1: Brute Force Detection (Windows Login Failures)",
        earliest="0"
    )
    all_assessments["Brute Force Attack"] = assess_severity("brute_force", result1)
    
    # ================================================
    # DETECTION 2: DNS Anomaly
    # ================================================
    query2 = """index=botsv3 earliest=0 sourcetype=stream:dns
    | mvexpand name{}
    | rename "name{}" as dns_query
    | eval query_length=len(dns_query)
    | where query_length > 40
    | stats count by dns_query, query_length
    | sort - query_length
    | head 10"""
    
    result2 = run_detection_query(
        service, query2,
        "ATTACK 2: DNS Anomaly Detection (Suspicious Domains)",
        earliest="0"
    )
    all_assessments["DNS Anomaly"] = assess_severity("dns_anomaly", result2)
    
    # ================================================
    # DETECTION 3: Web Attacks
    # ================================================
    query3 = """index=botsv3 earliest=0 sourcetype=stream:http status>=400
    | stats count by src_ip, status, http_method
    | sort - count
    | head 10"""
    
    result3 = run_detection_query(
        service, query3,
        "ATTACK 3: Web Attack Detection (HTTP Errors & XSS)",
        earliest="0"
    )
    all_assessments["Web Application Attack"] = assess_severity("web_attack", result3)
    
    # ================================================
    # DETECTION 4: Port Scanning
    # ================================================
    query4 = """index=botsv3 earliest=0 sourcetype=stream:tcp
    | stats dc(dest_port) as unique_ports, count as total_connections by src_ip
    | where unique_ports > 20
    | sort - unique_ports
    | head 10"""
    
    result4 = run_detection_query(
        service, query4,
        "ATTACK 4: Port Scanning Detection (Network Reconnaissance)",
        earliest="0"
    )
    all_assessments["Port Scanning"] = assess_severity("port_scan", result4)
    
    # ================================================
    # DETECTION 5: Data Exfiltration
    # ================================================
    query5 = """index=botsv3 earliest=0 sourcetype=stream:http
    | stats sum(bytes_out) as total_bytes_out by src_ip
    | eval MB_out=round(total_bytes_out/1024/1024, 2)
    | where MB_out > 50
    | sort - MB_out
    | head 10"""
    
    result5 = run_detection_query(
        service, query5,
        "ATTACK 5: Data Exfiltration Detection (Large Outbound Transfers)",
        earliest="0"
    )
    all_assessments["Data Exfiltration"] = assess_severity("data_exfil", result5)
    
    # ================================================
    # EXECUTIVE SUMMARY — Priority-Based Report
    # ================================================
    print_executive_summary(all_assessments)


if __name__ == "__main__":
    main()