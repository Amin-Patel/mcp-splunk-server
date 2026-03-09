# Week 3 Completion Report

## Project: Integration of MCP with Splunk
## Team Lead: Sayyed Abuzar
## Phase: 1 (POC Completion)

---

## Summary
Week 3 successfully bridged the Python backend with the Model Context Protocol (MCP). The system is now a fully functional AI-driven SOC assistant capable of executing Splunk queries via natural language.

---

## Technical Achievements (Captain) ✅
- [x] Implemented `FastMCP` server architecture.
- [x] Exposed Tool 1: `splunk_health_check`
- [x] Exposed Tool 2: `splunk_search`
- [x] Exposed Tool 3: `splunk_get_alerts`
- [x] Successfully connected Claude Desktop to the local Python process via JSON-RPC.
- [x] Implemented **Token Optimization** (Backend Shield) to strip useless Splunk metadata from JSON payloads, preventing LLM memory overflow.

## Team Contributions ✅
| Member | Week 3 Deliverables |
|--------|-------------------|
| **Mohammed Yahya** | Created BOTS v3 Golden Queries, verified triggered alerts, designed Splunk POC Dashboard for presentation. |
| **Patel Amin** | Mastered MCP Inspector, drafted QA Testing Protocol, conducted End-to-End stress tests, managed GitHub structure. |
| **Member 4** | Researched Claude Desktop configs, investigated HITL (Human-in-the-loop) architecture, drafted Phase 1 Technical Report. |

---

## Critical Bugs Fixed
1. **The Encoding Crash:** Claude crashed when receiving the `\u274c` (❌) emoji. Fixed by forcing `utf-8` encoding in `mcp_server.py`.
2. **The "Lost in Space" Bug:** Claude failed to attach because it couldn't locate `.env`. Fixed by adding explicit working directory tracking (`sys.path.insert`) to the server boot sequence.
3. **The Token Overflow Threat:** Splunk returned massive metadata payloads (`linecount`, `server_name`). Fixed by building a JSON pruner directly into the search tool.

---

## Project Status: PHASE 1 POC IS COMPLETE.
The architecture is proven. The AI can successfully query the SIEM. We are ready for the Project Review.