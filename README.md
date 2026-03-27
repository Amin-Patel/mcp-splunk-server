# Integration of MCP with Splunk for Enhanced Real-Time Cybersecurity Threat Monitoring

## 🎯 Project Overview
This project integrates the Model Context Protocol (MCP) with Splunk to enable real-time cybersecurity threat monitoring using AI-driven query execution. It allows seamless interaction between Claude and Splunk for automated analysis and alert retrieval.

## 🏗️ Architecture
User → Claude → MCP Client → MCP Server → Splunk

## 🛠️ Technology Stack
- Python 3.11+
- MCP Python SDK (Anthropic)
- Splunk Free Edition
- Claude Desktop
- BOTS v3 Dataset

## 📦 Current Status
*Phase 1 POC: COMPLETE ✅*
- 3 MCP Tools operational
- End-to-end pipeline tested
- Token optimization implemented

## 🔧 Tools Implemented
| Tool | Description |
|------|-------------|
| splunk_health_check | Verifies Splunk connectivity |
| splunk_search | Executes SPL queries via MCP |
| splunk_get_alerts | Fetches triggered alerts |

## 🚀 Quick Start
1. Clone the repository  
   git clone https://github.com/Amin-Patel/mcp-splunk-server.git  

2. Navigate to project directory  
   cd mcp-splunk-server  

3. Install dependencies  
   pip install -r requirements.txt  

4. Configure environment variables  
   Create a `.env` file with Splunk credentials  

5. Run MCP server  
   python server.py  

## 👥 Team
- Sayyed Abuzar — Team Lead & Core Developer
- Mohammed Yahya — Data & SPL Specialist
- Patel Mohammed Amin — Testing & Documentation Lead

## 📄 License
MIT License