"""
Unified Security Scanner for MCP-Splunk
========================================
Captain: Sayyed Abuzar
Created: Week 2, Day 4
Purpose: Complete security scanning system that combines all Week 2 work

This module:
1. Loads detection rules from detection_rules.py
2. Connects to Splunk via alert_fetcher.py
3. Runs all detection queries
4. Generates comprehensive security reports
5. Provides executive summaries for leadership

This becomes the foundation for Week 3 MCP tools!

FIXED: Added 'search' prefix for REST API compatibility
"""

import sys
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

# Import our modules
from splunk_config import get_splunk_config
from detection_rules import (
    get_all_rules,
    get_enabled_rules,
    get_critical_rules,
    get_high_priority_rules,
    get_rules_summary,
    Severity,
    Category,
    DetectionRule
)
from alert_fetcher import (
    connect_to_splunk,
    get_mcp_alerts,
    run_saved_search,
    generate_alert_summary
)

# Splunk SDK imports
import splunklib.client as client
import splunklib.results as results


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class ScanResult:
    """Result from scanning with a single detection rule."""
    rule_id: str
    rule_name: str
    severity: str
    category: str
    mitre_id: str
    status: str  # "ALERT", "CLEAR", "ERROR"
    result_count: int
    top_sources: List[str]
    sample_data: List[Dict]
    error_message: Optional[str] = None


@dataclass 
class ScanReport:
    """Complete scan report containing all results."""
    timestamp: str
    scan_duration_seconds: float
    total_rules_scanned: int
    alerts_triggered: int
    rules_clear: int
    rules_errored: int
    critical_alerts: List[ScanResult]
    high_alerts: List[ScanResult]
    medium_alerts: List[ScanResult]
    low_alerts: List[ScanResult]
    all_results: List[ScanResult]


# ============================================================
# SCANNER CLASS
# ============================================================

class SecurityScanner:
    """
    Unified Security Scanner that runs all detection rules against Splunk.
    
    Usage:
        scanner = SecurityScanner()
        report = scanner.run_full_scan()
        scanner.print_executive_summary(report)
    """
    
    def __init__(self, earliest: str = "-24h", latest: str = "now"):
        """
        Initialize the security scanner.
        
        Args:
            earliest: Start time for searches (default: last 24 hours)
            latest: End time for searches (default: now)
        """
        self.earliest = earliest
        self.latest = latest
        self.service = None
        self.connected = False
    
    def connect(self) -> bool:
        """
        Establish connection to Splunk.
        
        Returns:
            True if connected successfully, False otherwise
        """
        try:
            print("📡 Connecting to Splunk...")
            self.service = connect_to_splunk()
            self.connected = True
            print("✅ Connected to Splunk successfully!")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {str(e)}")
            self.connected = False
            return False
    
    def prepare_query(self, spl_query: str) -> str:
        """
        Prepare SPL query for REST API execution.
        
        The Splunk REST API requires queries to start with 'search' command.
        This method ensures all queries are properly formatted.
        
        Args:
            spl_query: The original SPL query
            
        Returns:
            Properly formatted SPL query for REST API
        """
        # Clean up the query
        query = spl_query.strip()
        
        # Remove leading/trailing whitespace and normalize
        query = ' '.join(query.split())
        
        # Check if query already starts with 'search' command
        # We need to be careful not to add 'search' if it's already there
        query_lower = query.lower()
        
        # List of commands that DON'T need 'search' prefix
        no_prefix_commands = [
            'search ', '| search', 'tstats', 'mstats', 
            'inputlookup', 'makeresults', 'datamodel'
        ]
        
        needs_prefix = True
        for cmd in no_prefix_commands:
            if query_lower.startswith(cmd):
                needs_prefix = False
                break
        
        # Add 'search' prefix if needed
        if needs_prefix:
            query = "search " + query
        
        return query
    
    def run_detection_rule(self, rule: DetectionRule) -> ScanResult:
        """
        Run a single detection rule against Splunk.
        
        Args:
            rule: The DetectionRule to execute
            
        Returns:
            ScanResult with findings
        """
        print(f"   🔍 Scanning: {rule.name}...", end=" ", flush=True)
        
        try:
            # Prepare the query with 'search' prefix for REST API
            spl_query = self.prepare_query(rule.spl_query)
            
            # Create the search job
            job = self.service.jobs.create(
                spl_query,
                **{
                    "earliest_time": self.earliest,
                    "latest_time": self.latest,
                    "exec_mode": "blocking"  # Wait for completion
                }
            )
            
            # Get results
            result_list = []
            for result in results.JSONResultsReader(job.results(output_mode="json")):
                if isinstance(result, dict):
                    result_list.append(result)
            
            # Extract top source IPs
            top_sources = []
            for r in result_list[:5]:
                # Try different field names for source IP
                src_ip = (
                    r.get("src_ip") or 
                    r.get("src") or 
                    r.get("source") or 
                    r.get("src_ip_addr") or
                    r.get("clientip") or
                    "Unknown"
                )
                if src_ip and src_ip != "Unknown" and str(src_ip) not in top_sources:
                    top_sources.append(str(src_ip))
            
            # Determine status
            if len(result_list) > 0:
                status = "ALERT"
                emoji = "⚠️"
            else:
                status = "CLEAR"
                emoji = "✅"
            
            print(f"{emoji} {status} ({len(result_list)} results)")
            
            return ScanResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity.value,
                category=rule.category.value,
                mitre_id=rule.mitre_id,
                status=status,
                result_count=len(result_list),
                top_sources=top_sources[:5],  # Top 5 sources
                sample_data=result_list[:3]   # First 3 results as sample
            )
            
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            return ScanResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity.value,
                category=rule.category.value,
                mitre_id=rule.mitre_id,
                status="ERROR",
                result_count=0,
                top_sources=[],
                sample_data=[],
                error_message=str(e)
            )
    
    def run_full_scan(self) -> ScanReport:
        """
        Run all enabled detection rules and generate comprehensive report.
        
        Returns:
            ScanReport with all findings
        """
        start_time = datetime.now()
        
        print("\n")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                                                              ║")
        print("║  🔐 MCP-SPLUNK SECURITY SCANNER                             ║")
        print("║                                                              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(f"\n⏰ Scan started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📅 Time range: {self.earliest} to {self.latest}")
        
        # Connect if not already connected
        if not self.connected:
            if not self.connect():
                print("❌ Cannot proceed without Splunk connection!")
                sys.exit(1)
        
        # Get all enabled rules
        rules = get_enabled_rules()
        print(f"\n📋 Running {len(rules)} detection rules...\n")
        print("-" * 60)
        
        # Run each rule
        all_results: List[ScanResult] = []
        for rule in rules:
            result = self.run_detection_rule(rule)
            all_results.append(result)
        
        print("-" * 60)
        
        # Calculate duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Categorize results
        alerts = [r for r in all_results if r.status == "ALERT"]
        clear = [r for r in all_results if r.status == "CLEAR"]
        errors = [r for r in all_results if r.status == "ERROR"]
        
        # Categorize by severity
        critical_alerts = [r for r in alerts if r.severity == "critical"]
        high_alerts = [r for r in alerts if r.severity == "high"]
        medium_alerts = [r for r in alerts if r.severity == "medium"]
        low_alerts = [r for r in alerts if r.severity == "low"]
        
        # Create report
        report = ScanReport(
            timestamp=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            scan_duration_seconds=duration,
            total_rules_scanned=len(rules),
            alerts_triggered=len(alerts),
            rules_clear=len(clear),
            rules_errored=len(errors),
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            low_alerts=low_alerts,
            all_results=all_results
        )
        
        return report
    
    def print_executive_summary(self, report: ScanReport):
        """
        Print executive summary of scan results.
        
        Args:
            report: The ScanReport to summarize
        """
        print("\n")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                                                              ║")
        print("║  📊 EXECUTIVE SUMMARY                                       ║")
        print("║                                                              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        
        # Overall status
        if report.rules_errored == report.total_rules_scanned:
            overall_status = "⚠️ SCAN ERROR"
            status_message = "All rules encountered errors. Check Splunk connection and data."
        elif report.alerts_triggered == 0:
            overall_status = "🟢 ALL CLEAR"
            status_message = "No threats detected in the scanned time range."
        elif len(report.critical_alerts) > 0:
            overall_status = "🔴 CRITICAL"
            status_message = "IMMEDIATE ACTION REQUIRED — Critical threats detected!"
        elif len(report.high_alerts) > 0:
            overall_status = "🟠 HIGH RISK"
            status_message = "High priority threats require investigation."
        else:
            overall_status = "🟡 MODERATE"
            status_message = "Some alerts detected, review recommended."
        
        print(f"\n   Overall Status: {overall_status}")
        print(f"   {status_message}")
        
        # Statistics
        print("\n   ┌─────────────────────────────────────────────────────┐")
        print(f"   │  Scan Time:        {report.timestamp:<30}│")
        print(f"   │  Duration:         {report.scan_duration_seconds:.2f} seconds{' '*21}│")
        print(f"   │  Rules Scanned:    {report.total_rules_scanned:<30}│")
        print(f"   │  Alerts Triggered: {report.alerts_triggered:<30}│")
        print(f"   │  Rules Clear:      {report.rules_clear:<30}│")
        print(f"   │  Errors:           {report.rules_errored:<30}│")
        print("   └─────────────────────────────────────────────────────┘")
        
        # Severity breakdown
        print("\n   📈 SEVERITY BREAKDOWN:")
        print(f"      🔴 Critical: {len(report.critical_alerts)}")
        print(f"      🟠 High:     {len(report.high_alerts)}")
        print(f"      🟡 Medium:   {len(report.medium_alerts)}")
        print(f"      🔵 Low:      {len(report.low_alerts)}")
        
        # Priority threats
        if report.alerts_triggered > 0:
            print("\n   🚨 PRIORITY THREATS:")
            print("   " + "-" * 55)
            
            # Show all alerts sorted by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_alerts = sorted(
                [r for r in report.all_results if r.status == "ALERT"],
                key=lambda x: severity_order.get(x.severity, 4)
            )
            
            for alert in sorted_alerts:
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵"
                }.get(alert.severity, "⚪")
                
                print(f"\n   {severity_emoji} [{alert.severity.upper()}] {alert.rule_name}")
                print(f"      Rule ID: {alert.rule_id}")
                print(f"      MITRE: {alert.mitre_id}")
                print(f"      Results: {alert.result_count}")
                
                if alert.top_sources:
                    print(f"      Top Sources: {', '.join(alert.top_sources[:3])}")
        
        # Show errors if any
        if report.rules_errored > 0:
            print("\n   ⚠️ RULES WITH ERRORS:")
            print("   " + "-" * 55)
            for result in report.all_results:
                if result.status == "ERROR":
                    print(f"   ❌ {result.rule_name}")
                    print(f"      Error: {result.error_message[:50]}...")
        
        print("\n" + "=" * 60)
    
    def print_detailed_report(self, report: ScanReport):
        """
        Print detailed technical report.
        
        Args:
            report: The ScanReport to detail
        """
        print("\n")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                                                              ║")
        print("║  📋 DETAILED TECHNICAL REPORT                               ║")
        print("║                                                              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        
        for result in report.all_results:
            status_emoji = {
                "ALERT": "⚠️",
                "CLEAR": "✅",
                "ERROR": "❌"
            }.get(result.status, "❓")
            
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵"
            }.get(result.severity, "⚪")
            
            print(f"\n{'─' * 60}")
            print(f"{status_emoji} {result.rule_name}")
            print(f"{'─' * 60}")
            print(f"   Rule ID:    {result.rule_id}")
            print(f"   Severity:   {severity_emoji} {result.severity.upper()}")
            print(f"   Category:   {result.category}")
            print(f"   MITRE ID:   {result.mitre_id}")
            print(f"   Status:     {result.status}")
            print(f"   Results:    {result.result_count}")
            
            if result.top_sources:
                print(f"   Top IPs:    {', '.join(result.top_sources)}")
            
            if result.sample_data and result.status == "ALERT":
                print(f"   Sample Data:")
                for i, sample in enumerate(result.sample_data[:2], 1):
                    # Show key fields from sample
                    try:
                        sample_str = json.dumps(sample, indent=6, default=str)
                        # Truncate if too long
                        if len(sample_str) > 200:
                            sample_str = sample_str[:200] + "..."
                        print(f"      [{i}] {sample_str}")
                    except:
                        print(f"      [{i}] (Data available)")
            
            if result.error_message:
                print(f"   Error:      {result.error_message}")
        
        print(f"\n{'═' * 60}")
    
    def generate_json_report(self, report: ScanReport) -> str:
        """
        Generate JSON report for API/LLM consumption.
        
        Args:
            report: The ScanReport to convert
            
        Returns:
            JSON string
        """
        report_dict = {
            "scan_info": {
                "timestamp": report.timestamp,
                "duration_seconds": report.scan_duration_seconds,
                "time_range": {
                    "earliest": self.earliest,
                    "latest": self.latest
                }
            },
            "summary": {
                "total_rules": report.total_rules_scanned,
                "alerts": report.alerts_triggered,
                "clear": report.rules_clear,
                "errors": report.rules_errored,
                "critical_count": len(report.critical_alerts),
                "high_count": len(report.high_alerts),
                "medium_count": len(report.medium_alerts),
                "low_count": len(report.low_alerts)
            },
            "alerts": [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "severity": r.severity,
                    "category": r.category,
                    "mitre_id": r.mitre_id,
                    "result_count": r.result_count,
                    "top_sources": r.top_sources
                }
                for r in report.all_results if r.status == "ALERT"
            ],
            "errors": [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "error": r.error_message
                }
                for r in report.all_results if r.status == "ERROR"
            ]
        }
        
        return json.dumps(report_dict, indent=2)
    
    def save_report(self, report: ScanReport, filename: str = None):
        """
        Save report to JSON file.
        
        Args:
            report: The ScanReport to save
            filename: Output filename (default: auto-generated)
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
        
        json_report = self.generate_json_report(report)
        
        with open(filename, "w") as f:
            f.write(json_report)
        
        print(f"\n💾 Report saved to: {filename}")


# ============================================================
# QUICK SCAN FUNCTIONS (For MCP Integration in Week 3)
# ============================================================

def quick_scan(earliest: str = "-24h", latest: str = "now") -> Dict:
    """
    Run a quick security scan and return results.
    This function will be used by MCP tools in Week 3.
    
    Args:
        earliest: Start time (default: last 24 hours)
        latest: End time (default: now)
    
    Returns:
        Dictionary with scan results
    """
    scanner = SecurityScanner(earliest=earliest, latest=latest)
    report = scanner.run_full_scan()
    return json.loads(scanner.generate_json_report(report))


def get_critical_alerts_only(earliest: str = "-24h", latest: str = "now") -> List[Dict]:
    """
    Get only critical alerts.
    This function will be used by MCP tools in Week 3.
    
    Args:
        earliest: Start time (default: last 24 hours)
        latest: End time (default: now)
    
    Returns:
        List of critical alert dictionaries
    """
    scanner = SecurityScanner(earliest=earliest, latest=latest)
    report = scanner.run_full_scan()
    
    return [
        {
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "mitre_id": r.mitre_id,
            "result_count": r.result_count,
            "top_sources": r.top_sources
        }
        for r in report.critical_alerts
    ]


def check_specific_ip(ip_address: str, earliest: str = "-7d", latest: str = "now") -> Dict:
    """
    Check if a specific IP appears in any alerts.
    This function will be used by MCP tools in Week 3.
    
    Args:
        ip_address: IP to check
        earliest: Start time (default: last 7 days)
        latest: End time (default: now)
        
    Returns:
        Dictionary with IP threat information
    """
    scanner = SecurityScanner(earliest=earliest, latest=latest)
    report = scanner.run_full_scan()
    
    ip_alerts = []
    for result in report.all_results:
        if result.status == "ALERT" and ip_address in result.top_sources:
            ip_alerts.append({
                "rule": result.rule_name,
                "severity": result.severity,
                "mitre_id": result.mitre_id
            })
    
    return {
        "ip": ip_address,
        "is_threat": len(ip_alerts) > 0,
        "alert_count": len(ip_alerts),
        "associated_attacks": ip_alerts
    }


# ============================================================
# MAIN
# ============================================================

def main():
    """Main entry point for the security scanner."""
    
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                                                              ║")
    print("║  🔐 MCP-SPLUNK UNIFIED SECURITY SCANNER                     ║")
    print("║                                                              ║")
    print("║  Week 2, Day 4 — Captain Abuzar                             ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    
    # ================================================================
    # IMPORTANT: Time Range Configuration
    # ================================================================
    # BOTS v3 dataset is from August 2018
    # If using BOTS v3, use: earliest="2018-08-01", latest="2018-08-31"
    # If using recent data, use: earliest="-7d", latest="now"
    # For all time, use: earliest="0", latest="now"
    # ================================================================
    
    # Try to detect best time range
    print("\n🔍 Detecting data time range...")
    
    try:
        # First, try with all time to find data
        scanner = SecurityScanner(earliest="0", latest="now")
        scanner.connect()
        
        # Quick test to see if we have data
        test_job = scanner.service.jobs.create(
            "search index=botsv3 | head 1 | stats count",
            exec_mode="blocking"
        )
        
        test_results = list(results.JSONResultsReader(test_job.results(output_mode="json")))
        
        if test_results and test_results[0].get("count", "0") != "0":
            print("✅ BOTS v3 data found! Using all-time search.")
            # Data exists, proceed with all time
        else:
            print("⚠️ No data in botsv3 index. Check if BOTS v3 is loaded.")
            
    except Exception as e:
        print(f"⚠️ Could not detect time range: {e}")
        print("   Proceeding with default settings...")
        scanner = SecurityScanner(earliest="0", latest="now")
    
    # Run full scan
    report = scanner.run_full_scan()
    
    # Print executive summary
    scanner.print_executive_summary(report)
    
    # Ask for detailed report
    print("\n" + "=" * 60)
    print("Do you want to see the detailed technical report? (y/n): ", end="")
    
    try:
        response = input().strip().lower()
        if response == 'y':
            scanner.print_detailed_report(report)
    except:
        pass  # If running non-interactively, skip detailed report
    
    # Save report
    scanner.save_report(report)
    
    # Final status
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                                                              ║")
    print("║  ✅ SECURITY SCAN COMPLETE                                  ║")
    print("║                                                              ║")
    print("║  This scanner will be integrated with MCP in Week 3!        ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("\n")
    
    # Return appropriate exit code
    if report.rules_errored == report.total_rules_scanned:
        return 1  # All errors
    elif report.rules_errored > 0:
        return 0  # Some errors but some success
    else:
        return 0  # All good


if __name__ == "__main__":
    sys.exit(main())