\# 🎯 MITRE ATT\&CK Mapping — MCP-Splunk Project



\## Overview



This document maps our detection rules to the MITRE ATT\&CK 

framework for standardized threat classification.



Reference: https://attack.mitre.org/



---



\## Detection Rules → ATT\&CK Mapping



\### 1. XSS Detection (MCP\_Detect\_XSS)



| Field | Value |

|-------|-------|

| \*Technique ID\* | T1059.007 |

| \*Technique Name\* | Command and Scripting Interpreter: JavaScript |

| \*Tactic\* | Execution |

| \*Description\* | Adversaries may abuse JavaScript for execution |

| \*Our Detection\* | Looks for <script>, javascript:, onerror=, onload= |

| \*Data Source\* | Web traffic (stream:http) |

| \*Severity\* | HIGH |



---



\### 2. SQL Injection (MCP\_Detect\_SQLi)



| Field | Value |

|-------|-------|

| \*Technique ID\* | T1190 |

| \*Technique Name\* | Exploit Public-Facing Application |

| \*Tactic\* | Initial Access |

| \*Description\* | Adversaries exploit vulnerabilities in web apps |

| \*Our Detection\* | Looks for SELECT, UNION, INSERT, DROP, 1=1 |

| \*Data Source\* | Web traffic (stream:http) |

| \*Severity\* | CRITICAL |



---



\### 3. Port Scan Detection (MCP\_Detect\_PortScan)



| Field | Value |

|-------|-------|

| \*Technique ID\* | T1046 |

| \*Technique Name\* | Network Service Discovery |

| \*Tactic\* | Discovery |

| \*Description\* | Adversaries scan for running services |

| \*Our Detection\* | IDS alerts from Suricata |

| \*Data Source\* | Network IDS (suricata) |

| \*Severity\* | MEDIUM |



---



\### 4. Brute Force (MCP\_Detect\_BruteForce)



| Field | Value |

|-------|-------|

| \*Technique ID\* | T1110 |

| \*Technique Name\* | Brute Force |

| \*Tactic\* | Credential Access |

| \*Description\* | Adversaries guess passwords through repetition |

| \*Our Detection\* | Multiple failed login attempts (>10) from same IP |

| \*Data Source\* | Authentication logs |

| \*Severity\* | HIGH |



---



\### 5. DNS Data Exfiltration (MCP\_Detect\_DataExfil)



| Field | Value |

|-------|-------|

| \*Technique ID\* | T1048.003 |

| \*Technique Name\* | Exfiltration Over Alternative Protocol: DNS |

| \*Tactic\* | Exfiltration |

| \*Description\* | Adversaries use DNS to exfiltrate data |

| \*Our Detection\* | Large DNS traffic (>1MB) from single source |

| \*Data Source\* | DNS logs (stream:dns) |

| \*Severity\* | CRITICAL |



---



\## ATT\&CK Tactics Covered



| Tactic | Techniques Covered |

|--------|-------------------|

| Initial Access | T1190 (SQLi) |

| Execution | T1059.007 (XSS) |

| Discovery | T1046 (Port Scan) |

| Credential Access | T1110 (Brute Force) |

| Exfiltration | T1048.003 (DNS Exfil) |



---



\## ATT\&CK Navigator Layer



For visual mapping, use: https://mitre-attack.github.io/attack-navigator/



Our techniques: T1059.007, T1190, T1046, T1110, T1048.003



---



\## Future Additions (Phase 2)



| Technique ID | Name | Status |

|--------------|------|--------|

| T1071 | Application Layer Protocol | Planned |

| T1059 | Command and Scripting Interpreter | Planned |

| T1083 | File and Directory Discovery | Planned |

| T1105 | Ingress Tool Transfer | Planned |



---



\## References



\- \[MITRE ATT\&CK Website](https://attack.mitre.org/)

\- \[ATT\&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

\- \[Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)



---



Document Version: 1.0

Created: Week 2, Day 3

Author: Patel Mohammed Amin

