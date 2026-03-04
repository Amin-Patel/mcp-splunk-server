"""
Detection Rules Module for MCP-Splunk
=====================================
Captain: Sayyed Abuzar
Created: Week 2, Day 3
Purpose: Centralized detection rules with severity and MITRE mapping

This module contains all security detection rules that:
- Are used by alert_fetcher.py
- Will be used by MCP tools in Week 3
- Map to MITRE ATT&CK framework
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


# ============================================================
# ENUMS FOR TYPE SAFETY
# ============================================================

class Severity(Enum):
    """Severity levels for detection rules"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    """Categories of attacks"""
    WEB_ATTACK = "web_attack"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    RECONNAISSANCE = "reconnaissance"


# ============================================================
# DETECTION RULE DATA CLASS
# ============================================================

@dataclass
class DetectionRule:
    """
    Represents a single detection rule.
    
    Attributes:
        rule_id: Unique identifier (e.g., "MCP_Detect_XSS")
        name: Human-readable name
        description: What this rule detects
        spl_query: The Splunk SPL query
        severity: Severity level
        category: Attack category
        mitre_id: MITRE ATT&CK ID
        mitre_tactic: MITRE ATT&CK Tactic
        enabled: Whether rule is active
    """
    rule_id: str
    name: str
    description: str
    spl_query: str
    severity: Severity
    category: Category
    mitre_id: str
    mitre_tactic: str
    enabled: bool = True


# ============================================================
# DETECTION RULES DATABASE
# ============================================================

DETECTION_RULES: Dict[str, DetectionRule] = {
    
    # ----------------------------------------------------------
    # WEB ATTACKS
    # ----------------------------------------------------------
    
    "MCP_Detect_XSS": DetectionRule(
        rule_id="MCP_Detect_XSS",
        name="XSS Attack Detection",
        description="Detects Cross-Site Scripting (XSS) attempts in web traffic",
        spl_query='''index=botsv3 sourcetype=stream:http 
| search "<script>" OR "javascript:" OR "onerror=" OR "onload="
| stats count by src_ip, dest_ip, uri_path
| where count > 0
| sort -count''',
        severity=Severity.HIGH,
        category=Category.WEB_ATTACK,
        mitre_id="T1059.007",
        mitre_tactic="Execution"
    ),
    
    "MCP_Detect_SQLi": DetectionRule(
        rule_id="MCP_Detect_SQLi",
        name="SQL Injection Detection",
        description="Detects SQL Injection attempts in web requests",
        spl_query='''index=botsv3 sourcetype=stream:http
| search "SELECT" OR "UNION" OR "INSERT" OR "DROP" OR "1=1"
| stats count by dest_ip, src_ip, uri_path, 
| where count > 0
| sort -count''',
        severity=Severity.CRITICAL,
        category=Category.WEB_ATTACK,
        mitre_id="T1190",
        mitre_tactic="Initial Access"
    ),
    
    # ----------------------------------------------------------
    # RECONNAISSANCE
    # ----------------------------------------------------------
    
    "MCP_Detect_PortScan": DetectionRule(
        rule_id="MCP_Detect_PortScan",
        name="Port Scan Detection",
        description="Detects port scanning activity using IDS alerts",
        spl_query='''index=botsv3
| stats dc(dest_port) as unique_ports count by src_ip
| where unique_ports > 20 OR count > 50
| sort -unique_ports''',
        severity=Severity.MEDIUM,
        category=Category.RECONNAISSANCE,
        mitre_id="T1046",
        mitre_tactic="Discovery"
    ),
    
    # ----------------------------------------------------------
    # AUTHENTICATION ATTACKS
    # ----------------------------------------------------------
    
    "MCP_Detect_BruteForce": DetectionRule(
        rule_id="MCP_Detect_BruteForce",
        name="Brute Force Authentication",
        description="Detects brute force login attempts",
        spl_query='''index=botsv3 sourcetype=*
| search "fail*" OR "invalid" OR "denied" OR "authentication"
| stats count by src_ip, user 
| where count > 10
| sort -count''',
        severity=Severity.HIGH,
        category=Category.AUTHENTICATION,
        mitre_id="T1110",
        mitre_tactic="Credential Access"
    ),
    
    # ----------------------------------------------------------
    # DATA EXFILTRATION
    # ----------------------------------------------------------
    
    "MCP_Detect_DataExfil": DetectionRule(
        rule_id="MCP_Detect_DataExfil",
        name="DNS Data Exfiltration",
        description="Detects large DNS traffic that may indicate data exfiltration",
        spl_query='''index=botsv3 sourcetype="stream:dns"
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes > 1000000
| sort -total_bytes''',
        severity=Severity.CRITICAL,
        category=Category.DATA_EXFILTRATION,
        mitre_id="T1048.003",
        mitre_tactic="Exfiltration"
    ),
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_all_rules() -> List[DetectionRule]:
    """Get all detection rules."""
    return list(DETECTION_RULES.values())


def get_enabled_rules() -> List[DetectionRule]:
    """Get only enabled detection rules."""
    return [rule for rule in DETECTION_RULES.values() if rule.enabled]


def get_rules_by_severity(severity: Severity) -> List[DetectionRule]:
    """Get rules filtered by severity level."""
    return [rule for rule in DETECTION_RULES.values() 
            if rule.severity == severity and rule.enabled]


def get_rules_by_category(category: Category) -> List[DetectionRule]:
    """Get rules filtered by category."""
    return [rule for rule in DETECTION_RULES.values() 
            if rule.category == category and rule.enabled]


def get_rule_by_id(rule_id: str) -> Optional[DetectionRule]:
    """Get a specific rule by its ID."""
    return DETECTION_RULES.get(rule_id)


def get_critical_rules() -> List[DetectionRule]:
    """Get all critical severity rules."""
    return get_rules_by_severity(Severity.CRITICAL)


def get_high_priority_rules() -> List[DetectionRule]:
    """Get critical and high severity rules."""
    return [rule for rule in DETECTION_RULES.values() 
            if rule.severity in [Severity.CRITICAL, Severity.HIGH] and rule.enabled]


def get_rules_summary() -> Dict:
    """Get a summary of all rules."""
    all_rules = get_all_rules()
    enabled_rules = get_enabled_rules()
    
    severity_counts = {}
    for severity in Severity:
        severity_counts[severity.value] = len(get_rules_by_severity(severity))
    
    category_counts = {}
    for category in Category:
        category_counts[category.value] = len(get_rules_by_category(category))
    
    return {
        "total_rules": len(all_rules),
        "enabled_rules": len(enabled_rules),
        "disabled_rules": len(all_rules) - len(enabled_rules),
        "by_severity": severity_counts,
        "by_category": category_counts
    }


def print_rules_dashboard():
    """Print a formatted dashboard of all rules."""
    
    print("\n" + "=" * 70)
    print("🔐 MCP-SPLUNK DETECTION RULES")
    print("=" * 70)
    
    # Table header
    print(f"\n{'RULE ID':<25} {'SEVERITY':<12} {'MITRE':<12} {'CATEGORY':<20}")
    print("-" * 70)
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_rules = sorted(get_all_rules(), 
                          key=lambda x: severity_order.get(x.severity.value, 5))
    
    for rule in sorted_rules:
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪"
        }.get(rule.severity.value, "⚪")
        
        status = "✅" if rule.enabled else "❌"
        
        print(f"{severity_emoji} {rule.rule_id:<23} {rule.severity.value:<12} "
              f"{rule.mitre_id:<12} {rule.category.value:<20} {status}")
    
    # Summary
    summary = get_rules_summary()
    print("\n" + "-" * 70)
    print(f"📊 Total: {summary['total_rules']} | "
          f"Enabled: {summary['enabled_rules']} | "
          f"Critical: {summary['by_severity']['critical']} | "
          f"High: {summary['by_severity']['high']}")
    print("=" * 70)
    
    # MITRE Coverage
    print("\n🎯 MITRE ATT&CK COVERAGE:")
    for rule in sorted_rules:
        print(f"   {rule.mitre_id} ({rule.mitre_tactic}) → {rule.name}")
    
    print("\n✅ Detection Rules Module Ready!")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print_rules_dashboard()