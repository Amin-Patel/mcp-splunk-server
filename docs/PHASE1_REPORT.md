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

4.1 Overall Architecture

The system follows a 5-layer architecture designed to enable seamless interaction between a security analyst and Splunk SIEM using natural language.

Layer 1: User Interface (Analyst)
The security analyst interacts with the system by typing natural language queries (e.g., “Show me failed logins”). This eliminates the need to manually write complex SPL queries.

Layer 2: LLM (Claude)
Claude interprets the analyst’s query, understands intent, and determines the appropriate tool (e.g., splunk_search) to fulfill the request. It acts as the reasoning and orchestration layer.

Layer 3: MCP Client (Claude Desktop)
The MCP Client manages communication between Claude and the backend server using the MCP (Model Context Protocol). It converts tool calls into structured JSON-RPC requests.

Layer 4: MCP Server (Our Project)
The MCP Server receives tool calls from the MCP Client, processes them, and executes corresponding operations on Splunk. It also formats and sanitizes results before returning them.

Layer 5: Splunk SIEM
Splunk stores and indexes security event data. It executes SPL (Search Processing Language) queries and returns raw results to the MCP Server.

Data Flow:

Forward flow:
User → Claude → MCP Client → MCP Server → Splunk

Return flow:
Splunk → MCP Server → MCP Client → Claude → User

This layered architecture ensures modularity, scalability, and clear separation of responsibilities.

4.2 Technology Stack

Python (Backend - MCP Server)
Python is used to implement the MCP Server due to its simplicity, readability, and strong ecosystem for building APIs and integrating with external systems like Splunk.

Splunk SIEM
Splunk is a leading SIEM platform capable of ingesting, indexing, and searching large volumes of security data. It provides powerful SPL queries for threat detection and analysis.

MCP (Model Context Protocol)
MCP standardizes communication between LLMs and external tools. It enables structured, secure, and extensible tool invocation, making it ideal for integrating Claude with backend services.

Claude (LLM)
Claude is used for natural language understanding and reasoning. It translates user queries into actionable tool calls and converts technical results into human-readable insights.

Splunk BOTS v3 Dataset
The BOTS v3 dataset provides realistic simulated enterprise security data. It is used for testing and demonstrating detection capabilities in a controlled environment.

4.3 Data Flow

The system processes analyst queries through the following steps:

The analyst types a query:
"Show me failed logins"
Claude interprets the query and decides to call the appropriate tool (splunk_search).
The MCP Client sends a JSON-RPC request to the MCP Server with the required parameters.
The MCP Server constructs and executes an SPL query via the Splunk REST API.
Splunk processes the query and returns raw results.
The MCP Server applies the Backend Shield, removing unnecessary metadata and sensitive fields.
The cleaned JSON response is sent back to the MCP Client.
Claude applies the Prompt Shield, leveraging tool docstrings and context to interpret results safely.
Claude generates a human-readable analysis of the results.
The analyst receives the final response in natural language.

This flow ensures secure, structured, and interpretable interaction between the analyst and the SIEM system.## 5. Methodology

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
