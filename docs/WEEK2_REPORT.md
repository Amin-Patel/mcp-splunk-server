\# 📊 WEEK 2 REPORT — MCP-SPLUNK PROJECT



\## Project Information

\- Project Title: Integration of MCP with Splunk for Enhanced Real-Time Cybersecurity Threat Monitoring

\- Team: Sayyed Abuzar (Captain), Mohammed Yahya, Patel Mohammed Amin, Member 4

\- Week: 2 of 4

\- Phase: 1 (Foundation + POC)

\- Report Date: 03 March 2026



---



\## Week 2 Objectives



| Objective | Status |

|-----------|--------|

| Load BOTS v3 dataset into Splunk | Complete |

| Practice SPL security queries | Complete |

| Build attack detection Python scripts | Complete |

| Create automated detection rules | Complete |

| Map detections to MITRE ATT\&CK | Complete |



---



\## Daily Progress



\### Day 1: Data Loading \& Exploration

\- Loaded BOTS v3 dataset (2+ million events)

\- Explored 15+ sourcetypes

\- Identified key security data sources

\- Files created: Basic exploration queries



\### Day 2: Attack Detection

\- Discovered 3 confirmed attacks:

&nbsp; - XSS Attack from IP: 61.75.35.114

&nbsp; - Port Scanning from IP: 192.168.8.103

&nbsp; - Data Exfiltration from IP: 172.16.133.131

\- Files created: attack\_detector.py, test\_attack\_detection.py



\### Day 3: Detection Rules \& Integration

\- Created 5 automated detection rules

\- Built alert fetching system via REST API

\- Mapped all rules to MITRE ATT\&CK framework

\- Files created: detection\_rules.py, alert\_fetcher.py, MITRE\_MAPPING.md



\### Day 4: Full Integration \& Reporting

\- Created unified security scanner

\- Validated all detection rules

\- Prepared Week 2 documentation

\- Files created: security\_scanner.py, WEEK2\_REPORT.md



---



\## Files Created This Week



| File | Purpose | Author |
|------|---------|--------|
| splunk_config.py | Splunk connection configuration | Abuzar |
| attack_detector.py | Manual attack detection | Abuzar |
| detection_rules.py | Automated detection rules | Abuzar |
| alert_fetcher.py | Fetch alerts via REST API | Abuzar |
| security_scanner.py | Unified security scanner | Abuzar |
| MITRE_MAPPING.md | MITRE ATT&CK mapping | Amin |
| DETECTION_RESULTS.md | Rule validation results | Yahya |
| WEEK2_REPORT.md | This report | Amin |

---



\## Detection Rules Summary


## Detection Rules Summary

| Rule ID | Name | Severity | MITRE ID |
|---------|------|----------|----------|
| MCP_Detect_XSS | XSS Attack Detection | HIGH | T1059.007 |
| MCP_Detect_SQLi | SQL Injection Detection | CRITICAL | T1190 |
| MCP_Detect_PortScan | Port Scan Detection | MEDIUM | T1046 |
| MCP_Detect_BruteForce | Brute Force Detection | HIGH | T1110 |
| MCP_Detect_DataExfil | Data Exfiltration Detection | CRITICAL | T1048.003 |



---

## Threats Identified

| Threat Type | Attacker IP | Severity | Evidence |
|-------------|-------------|----------|----------|
| XSS Attack | 61.75.35.114 | HIGH | Script injection in HTTP |
| Port Scanning | 192.168.8.103 | MEDIUM | Suricata IDS alerts |
| Data Exfiltration | 172.16.133.131 | CRITICAL | Large DNS transfers |

---



\## Technical Achievements



\- Python-Splunk REST API integration successful

\- Automated detection rules module created

\- MITRE ATT\&CK mapping completed

\- Modular architecture ready for MCP integration


## Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| Splunk field names vary by sourcetype | Used field discovery queries |
| Large dataset (2M+ events) | Used time-bounded queries |
| Team coordination | Used WhatsApp + clear task sheets |

---




## Week 3 Preview

Next week we build the actual MCP Server with 3 tools:
1. splunk_search — Execute SPL queries via MCP
2. splunk_get_alerts — Fetch alerts via MCP
3. splunk_health_check — Check Splunk status via MCP
---


## Team Contributions

| Member | Role | Contributions |
|--------|------|---------------|
| Sayyed Abuzar | Captain | Python scripts, architecture, integration |
| Mohammed Yahya | Splunk Engineer | SPL queries, Splunk alerts, validation |
| Patel Mohammed Amin | Deputy | Documentation, MITRE mapping, GitHub |
| [Member 4] | Research | IR playbooks, literature review |

---
Report prepared by: Patel Mohammed Amin

Reviewed by: Sayyed Abuzar

