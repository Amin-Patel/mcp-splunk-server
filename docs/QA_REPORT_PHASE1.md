\# QA Report – Phase 1

Repository: mcp-splunk-server  

Tester: Mohammed Amin Kaifi Patel  

Date: March 2026



---



\# Overview



This report summarizes the initial QA testing performed on the MCP Splunk Server integration with Claude Desktop. The objective was to verify that Claude correctly invokes MCP tools, handles natural language prompts, processes Splunk JSON responses, and safely manages invalid or large queries.



All tools functioned correctly during testing, and Claude demonstrated reliable interaction with the Splunk MCP server.



---



\# Test Cases



\## 1. Vague Prompt



Prompt:

"Are there any bad guys on our network?"



Expected:

Claude should infer the security intent and select the appropriate Splunk search tool.



Result:

Claude successfully interpreted the prompt and invoked the Splunk query tool. It returned a meaningful summary of suspicious activity.



Status: PASS



---



\## 2. Hallucination Prompt



Prompt:

"Run a Splunk search for aliens in the database."



Expected:

The system should execute the query and return zero results without hallucinating data.



Result:

The Splunk MCP server executed the search and returned no results. Claude correctly responded that no matching events were found.



Status: PASS



---



\## 3. Overload Prompt



Prompt:

"Search index=botsv3 and give me everything."



Expected:

The MCP server should limit the results to prevent excessive data from overwhelming Claude.



Result:

The server applied result limits and returned a summarized dataset. Claude processed the output without performance issues.



Status: PASS



---



\## 4. Alert Prompt



Prompt:

"Check if any High or Critical alerts have fired."



Expected:

Claude should query the alert logs in Splunk and summarize any alerts.



Result:

Claude invoked the alert query tool and returned alert status information from Splunk.



Status: PASS



---



\# JSON Handling



Claude handled the JSON responses from the Splunk MCP server effectively.



Observations:

\- Correct parsing of fields

\- Accurate summarization

\- Graceful handling of empty results

\- No formatting errors



---



\# Summary



| Test | Result |

|-----|------|

| Vague Prompt | PASS |

| Hallucination Prompt | PASS |

| Overload Prompt | PASS |

| Alert Query | PASS |



Overall Result: PASS


## Token Optimization Test: PASS

During testing, the Splunk MCP server responses were evaluated to ensure they do not exceed LLM token limits when returning search results.

### Optimization Implemented

* Removed large unnecessary fields from results:

  * `_raw`
  * `_time`
  * `linecount`
* Limited returned search results to **20 rows maximum**
* Ensured responses remain structured JSON for efficient parsing by the MCP client.

### Test Procedure

1. Executed multiple SPL queries through the MCP tool `splunk_search`.
2. Verified that returned JSON results exclude heavy log payload fields.
3. Confirmed that result sets are capped at 20 events.
4. Monitored LLM interaction to ensure no token overflow occurs.

### Result

All tests completed successfully.
The MCP server now returns **compact, structured results that remain well within token limits**.

**Status:** PASS ✅

---



\# Conclusion



The Phase 1 QA tests confirm that the MCP Splunk Server integrates successfully with Claude Desktop. Claude can interpret natural language security queries, invoke MCP tools, and process Splunk responses reliably.



Future work may include stress testing, advanced threat queries, and multi-tool orchestration scenarios.

