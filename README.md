\# MCP-Splunk: AI-Powered Security Operations



\## Project Overview



Integration of Model Context Protocol (MCP) with Splunk for Enhanced Real-Time Cybersecurity Threat Monitoring and Response.



---



| Phase | Semester | Status |

|-------|----------|--------|

| Phase 1 | 4th | 🔄 In Progress (Week 2 of 4) |

| Phase 2 | 5th | ⏳ Planned |

| Phase 3 | 6th | ⏳ Planned |



---



\## Week 2 Achievements



\- BOTS v3 dataset loaded (2M+ events)

\- 5 detection rules created

\- Python-Splunk integration working

\- MITRE ATT\&CK mapping complete

\- Alert fetching via REST API



---



\## Project Structure

&nbsp;mcp-splunk/

├── splunk\_config.py # Splunk connection config

├── attack\_detector.py # Attack detection module

├── detection\_rules.py # Detection rules engine

├── alert\_fetcher.py # Alert fetching module

├── security\_scanner.py # Unified scanner

├── test\_\*.py # Test scripts

└── docs/

├── MITRE\_MAPPING.md # MITRE ATT\&CK mapping

├── DETECTION\_RESULTS.md # Validation results

└── WEEK2\_REPORT.md # Week 2 report

---



\## Team



Sayyed Abuzar – Captain,Lead Developer

Patel Mohammed Amin – Deputy, Documentation Lead  

Mohammed Yahya – Splunk Engineer  

Alkam Khan – Research - \& Documentation





---



\## Technology Stack



Python 3.12  

Splunk Enterprise 10.2.0  

MCP Python SDK  

BOTS v3 Dataset  



---



\## Quick Start



```bash

\# Clone repository

git clone \[repo-url]

cd mcp-splunk



\# Install dependencies

pip install splunk-sdk



\# Test connection

python test\_connection.py



\# Run security scanner

python security\_scanner.py





Last Updated: 03 March 2026

