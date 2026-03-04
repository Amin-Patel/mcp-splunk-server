### Purpose

This document defines the exact SPL queries and the exact fields returned by Splunk for each of the five primary attack detections used in our AI-driven security monitoring system.
The purpose of this schema definition is to ensure that the AI engine (via security_scanner.py) clearly understands:
What data is being returned
What each column represents
How to interpret the results correctly
This acts as the “Golden Rules” schema for AI interpretation.

### 1. Cross-Site Scripting (XSS)
SPL Query:
index=main ("<script>" OR "javascript:" OR "onerror=" OR "onload=")
| stats count by src_ip, dest_ip, uri_path
| sort -count

### Return Field Name:
| Field Name | Meaning                               |
| ---------- | ------------------------------------- |
| src_ip     | IP address of the attacker            |
| dest_ip    | Target server IP address              |
| uri_path   | Requested URL endpoint                |
| count      | Total number of detected XSS attempts |

### Schema Format for AI:
src_ip, dest_ip, uri_path, count


### 2.SQL Injection (SQLi)

index=main ("' OR 1=1" OR "UNION SELECT" OR "SELECT * FROM" OR "DROP TABLE")
| stats count by src_ip, dest_ip, uri_path
| sort -count

| Field Name | Meaning                                |
| ---------- | -------------------------------------- |
| src_ip     | IP address initiating the attack       |
| dest_ip    | Target database/server IP              |
| uri_path   | Targeted endpoint                      |
| count      | Total number of SQL injection attempts |

### Schema Format for AI:
src_ip, dest_ip, uri_path, count

### 3.Port Scan Detection

### SPL Query:

index=botsv3
| stats dc(dest_port) as unique_ports count by src_ip
| where unique_ports > 20 OR count > 50
| sort -unique_ports

### Returned Fields:
| Field Name   | Meaning                                      |
| ------------ | -------------------------------------------- |
| src_ip       | Source IP performing scan                    |
| unique_ports | Number of distinct destination ports scanned |
| count        | Total connection attempts                    |

### Schema Format for AI:
src_ip, unique_ports, count


### 4.Brute Force Attack Detection

### SPL Query:

index=main ("Failed password" OR "authentication failed")
| stats count by src_ip, user
| where count > 10
| sort -count

| Field Name | Meaning                         |
| ---------- | ------------------------------- |
| src_ip     | Attacker IP address             |
| user       | Target username                 |
| count      | Number of failed login attempts |

### Schema Format for AI:
src_ip, user, count

### 5.Data Exfiltration Detection

### SPL Query:
index=main
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes > 10000000
| sort -total_bytes

| Field Name  | Meaning                                  |
| ----------- | ---------------------------------------- |
| src_ip      | Internal source IP                       |
| dest_ip     | External destination IP                  |
| total_bytes | Total outbound data transferred in bytes |

### Schema Format for AI
src_ip, dest_ip, total_bytes