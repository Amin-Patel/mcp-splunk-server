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
This tool verifies connectivity with the Splunk server and ensures that the system is operational.

### 6.2 splunk_search
This tool executes SPL queries dynamically through MCP and returns structured results.

### 6.3 splunk_get_alerts
This tool fetches triggered alerts from Splunk, enabling real-time monitoring of security events.

---

## 7. Testing & Results

### 7.1 Test Scenarios
Multiple test scenarios were executed, including connectivity checks, query execution, and alert retrieval.

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
