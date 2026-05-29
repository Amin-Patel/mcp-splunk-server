# Phase 1 Technical Report

## 1. Abstract
This project presents the integration of the Model Context Protocol (MCP) with Splunk to enable real-time cybersecurity threat monitoring using AI-driven automation. The system allows seamless interaction between Claude Desktop and Splunk through a custom MCP server, enabling efficient query execution, alert retrieval, and system health monitoring. Phase 1 focuses on building a functional prototype, implementing core tools, and optimizing token usage for efficient communication.

---

## 2. Introduction

### 2.1 Problem Statement
Traditional cybersecurity monitoring relies heavily on manual querying and analysis in Splunk, which is time-consuming and requires expertise in SPL (Search Processing Language). This limits rapid response to threats and increases operational overhead.

### 2.2 Objectives
- Integrate MCP with Splunk for automated interaction
- Enable AI-driven execution of SPL queries
- Retrieve alerts and system status in real time
- Optimize token usage for efficient communication

### 2.3 Scope of Phase 1
Phase 1 focuses on developing a Proof of Concept (POC) system with core MCP tools, establishing end-to-end communication, and validating functionality using test scenarios.

---

## 3. Literature Review
The literature review includes studies on AI-driven cybersecurity, SIEM systems like Splunk, and protocol-based integrations. Existing systems lack seamless AI integration for automated threat analysis, highlighting the need for MCP-based solutions.

---

## 4. System Architecture

### 4.1 Overall Architecture
The system follows a modular architecture:

User → Claude Desktop → MCP Client → MCP Server → Splunk

### 4.2 Technology Stack
- Python 3.11+
- MCP Python SDK (Anthropic)
- Splunk Free Edition
- Claude Desktop
- BOTS v3 Dataset

### 4.3 Data Flow
1. User sends a query through Claude
2. MCP Client processes the request
3. MCP Server maps it to a tool
4. Splunk executes the query
5. Results are returned to the user

---

## 5. Methodology

### 5.1 Environment Setup
Python environment configured with required dependencies and Splunk instance set up locally using the Free Edition.

### 5.2 Data Preparation (BOTS v3)
The BOTS v3 dataset was used to simulate real-world cybersecurity events, containing millions of log entries for testing detection and analysis.

### 5.3 MCP Server Development
A custom MCP server was developed to handle communication between Claude and Splunk, enabling tool-based execution.

### 5.4 Tool Implementation
Three core tools were implemented:
- splunk_health_check
- splunk_search
- splunk_get_alerts

### 5.5 Token Optimization (Double Shield)
A token optimization mechanism was implemented to reduce unnecessary data transfer and improve efficiency during communication.

---

## 6. Implementation

### 6.1 splunk_health_check

**Purpose:** Verify Splunk server connectivity and status

**Implementation:**
- Connects to Splunk REST API using splunklib
- Retrieves server info, version, and available indexes
- Returns JSON with connection status

**Code highlights:**
```python
def splunk_health_check():
    service = connect_to_splunk()
    info = service.info
    indexes = service.indexes
    return {
        "status": "connected",
        "version": info["version"],
        "index_count": len(indexes)
    }

Why this matters:
Standard SOC workflow — analysts always verify system
health before starting investigation.

### 6.2 splunk_search

**Purpose:** Execute SPL queries via natural language

**Implementation:**

Accepts SPL query string from Claude
Executes search via Splunk REST API
Applies Backend Shield to strip metadata
Returns clean JSON to LLM
Backend Shield logic:

Python

# Strip non-essential fields before sending to LLM
essential_fields = ['src_ip', 'dest_ip', 'user', 
                   'action', 'status', 'uri_path']
cleaned_results = [{k: v for k, v in event.items() 
                   if k in essential_fields} 
                   for event in raw_results]

**Token optimization:**
Original Splunk response: ~15,000 tokens
After Backend Shield: ~6,000 tokens
Reduction: 60%

**Why this matters:**
This is the CORE tool. Everything else builds on the
ability to query Splunk conversationally.

### 6.3 splunk_get_alerts

**Purpose:** Fetch triggered alerts by severity

**Implementation:**

Queries Splunk's saved searches (alerts)
Filters by severity (critical/high/medium/low)
Returns alert metadata (name, severity, trigger time)

**Code highlights:**

Python

def splunk_get_alerts(severity="all"):
    alerts = service.saved_searches
    triggered = [a for a in alerts if a.is_scheduled 
                 and a.alert_count > 0]
    if severity != "all":
        triggered = [a for a in triggered 
                    if a.severity == severity]
    return triggered

**Why this matters:**
Alert monitoring is a core SOC function. This tool
automates what normally requires navigating through
Splunk's UI.

### 6.4 Double Shield Architecture

**Explain the two-layer optimization strategy:**

**Backend Shield (Code-level):**

JSON pruner strips Splunk metadata before LLM sees it
Fields like _time, host, index, linecount removed
Only security-relevant fields preserved
Implemented in: splunk_search tool

**Prompt Shield (LLM-level):**

Tool docstrings contain AI instructions
Example: "CRITICAL AI INSTRUCTION: To save token
context, only analyze the provided fields..."
Claude reads these and adapts behavior accordingly
Prevents verbose, wasteful responses
Combined effect:
Token reduction: ~60%
Prevents context window overflow
Enables longer investigation sessions without restart

## 7. Testing & Results

### 7.1 Test Scenarios
We tested 5 real-world security investigation scenarios:

Scenario 1: System Health Check

Objective: Verify Splunk is operational
Tool used: splunk_health_check
Result: ✅ Server status confirmed in <10 seconds

Scenario 2: Brute Force Attack Detection

Objective: Identify IPs with excessive failed logins
Query: "Show me IPs with failed authentication attempts"
Tool used: splunk_search
Result: ✅ Top 10 attacking IPs identified in 30 seconds
Manual equivalent: 10-15 minutes

Scenario 3: Threat Actor Investigation

Objective: Deep dive on suspicious IP from Scenario 2
Query: "Show me all activity from [suspicious IP]"
Tool used: splunk_search (follow-up query)
Result: ✅ Full activity timeline in 30 seconds
Manual equivalent: 15-20 minutes

Scenario 4: Alert Status Check

Objective: Review triggered security alerts
Tool used: splunk_get_alerts
Result: ✅ All active alerts retrieved in 15 seconds
Manual equivalent: 5 minutes (navigating UI)

Scenario 5: Incident Summary

Objective: Generate complete investigation summary
Result: ✅ AI synthesized all findings in 30 seconds
Manual equivalent: 15-20 minutes (manual report writing)

### 7.2 Performance Comparison (Manual vs AI)
The AI-driven approach significantly reduced query execution time and simplified interaction compared to manual SPL usage.

### 7.3 Demo Results
The system successfully demonstrated end-to-end functionality, with all tools operating correctly and returning expected outputs.

---

## 8. Challenges Faced
- Encoding issues during data handling
- Environment variable (.env) configuration errors
- Token overflow during large query responses

---

## 9. Future Work (Phase 2 & 3)
- Advanced threat detection using AI models
- Integration with additional SIEM tools
- Real-time dashboards and visualization
- Deployment in cloud environments

---

## 10. References
- Splunk Documentation
- Anthropic MCP Documentation
- BOTS v3 Dataset
