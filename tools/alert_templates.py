"""
============================================================
ALERT TEMPLATES - Pre-built Security Detection Rules
============================================================
Project  : MCP Server for Splunk
Research : Amin (Milestone 3, Day 2)
Code     : Abuzar

Purpose:
    Pre-built security alert templates Claude can deploy
    instantly via natural language.
============================================================
"""


CRON_PRESETS = {
    "every_minute":     "* * * * *",
    "every_5_minutes":  "*/5 * * * *",
    "every_10_minutes": "*/10 * * * *",
    "every_15_minutes": "*/15 * * * *",
    "every_30_minutes": "*/30 * * * *",
    "every_hour":       "0 * * * *",
    "every_day":        "0 0 * * *",
    "every_monday_8am": "0 8 * * 1",
}


ALERT_TEMPLATES = {

    "brute_force": {
        "name":            "BruteForce_FailedLogins",
        "description":     "Detects more than 50 failed login attempts from the same IP within 10 minutes",
        "spl_query":       'index=botsv3 (fail* OR "invalid password") | stats count by src_ip | where count > 50',
        "severity":        "HIGH",
        "cron_schedule":   "*/10 * * * *",
        "threshold":       0,
        "category":        "Authentication",
        "mitre_technique": "T1110 - Brute Force",
    },

    "port_scan": {
        "name":            "PortScan_Detection",
        "description":     "Detects when a single IP connects to more than 20 different destination ports",
        "spl_query":       "index=botsv3 | stats dc(dest_port) as unique_ports by src_ip | where unique_ports > 20",
        "severity":        "MEDIUM",
        "cron_schedule":   "*/5 * * * *",
        "threshold":       0,
        "category":        "Reconnaissance",
        "mitre_technique": "T1046 - Network Service Scanning",
    },

    "dns_anomaly": {
        "name":            "DNS_LongQuery_Anomaly",
        "description":     "Detects unusually long DNS queries indicating possible DNS tunneling",
        "spl_query":       "index=botsv3 sourcetype=dns | eval query_length=len(query) | where query_length > 100 | table _time src_ip query query_length",
        "severity":        "MEDIUM",
        "cron_schedule":   "*/15 * * * *",
        "threshold":       0,
        "category":        "Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
    },

    "http_error_spike": {
        "name":            "HTTP_5xx_ErrorSpike",
        "description":     "Detects more than 100 HTTP 5xx server errors within a 5-minute window",
        "spl_query":       "index=botsv3 status>=500 status<600 | stats count | where count > 100",
        "severity":        "LOW",
        "cron_schedule":   "*/5 * * * *",
        "threshold":       0,
        "category":        "Availability",
        "mitre_technique": "T1499 - Endpoint Denial of Service",
    },

    "suspicious_login": {
        "name":            "User_MultiCountry_Login",
        "description":     "Detects when a user logs in from multiple countries",
        "spl_query":       "index=botsv3 action=login | stats values(country) as countries count by user | where mvcount(countries) > 1",
        "severity":        "HIGH",
        "cron_schedule":   "*/30 * * * *",
        "threshold":       0,
        "category":        "Credential Access",
        "mitre_technique": "T1078 - Valid Accounts",
    },
}


def list_template_names():
    """Return all available template keys."""
    return list(ALERT_TEMPLATES.keys())


def get_template(template_key):
    """Retrieve a template by key."""
    return ALERT_TEMPLATES.get(template_key.lower())


def get_templates_summary():
    """Return a lightweight summary of all templates."""
    return [
        {
            "key":             key,
            "name":            t["name"],
            "category":        t["category"],
            "severity":        t["severity"],
            "mitre_technique": t["mitre_technique"],
            "description":     t["description"],
        }
        for key, t in ALERT_TEMPLATES.items()
    ]