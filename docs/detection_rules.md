### Detection Rules Validation Results
### Test Date: March 3, 2026
### Tested By: Mohammed Yahya

### Summary Table
Rule	Results Found	Top Attacker        IP	Severity
XSS	        0	            N/A	            HIGH
SQLi	    9	        192.168.3.130	    CRITICAL
Port Scan	0	            N/A	            MEDIUM
Brute Force	0	            N/A	            HIGH
Data Exfil	0	            N/A	            CRITICAL


### Detailed Findings
### SQL Injection (SQLi)
 * Status: Confirmed. * Observation: The search for SQL keywords (SELECT, UNION, INSERT, etc.) within stream:http returned 9 events. All activity originated from IP 192.168.3.130, targeting various WordPress directories and image files.

### XSS (Cross-Site Scripting)
 * Status: No Results Found.

### Observation
 The search for script tags and JavaScript event handlers (<script>, onerror, etc.) returned 0 events.
 Port Scan (Suricata Alerts): * Status: No Results Found.

###	Observation
 The Suricata alert index returned 0 events for the specified threshold (count > 5).
 Brute Force: * Status: No Results Found.

###	Observation
 While there were 41,018 general events in the index, the specific filter for authentication failure keywords (fail*, denied, invalid) combined with the count > 10 threshold yielded no matches.
 Data Exfiltration: * Status: No Results Found.

###	Observation
 DNS stream logs showed 218,456 events, but no single source IP exceeded the 1MB threshold (total_bytes > 1000000) defined in the rule.

