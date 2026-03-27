# 🎬 GOD-MODE DEMO SCRIPT — Phase 1 POC
# Project: Integration of MCP with Splunk
# Presenter: Sayyed Abuzar (Team Lead)

---

## SETUP BEFORE DEMO
- [ ] Splunk is running with BOTS v3 data loaded
- [ ] MCP Server is running (no errors in terminal)
- [ ] Claude Desktop is open and showing 3 tools
- [ ] Screen recorder is ON (if recording)

---

## SCENE 1: "THE HANDSHAKE" — Health Check
**What we're showing:** Our system can verify Splunk is alive.

**Type this into Claude Desktop:**
Hey Claude, I'm a security analyst starting my shift.
Before I begin, can you check if our Splunk SIEM server
is online and healthy? I need to know the server status,
version, and how many indexes we have.

**Expected behavior:**
- Claude calls `splunk_health_check` tool
- Returns: server status (connected), Splunk version, index count
- Claude adds context like "Your SIEM is healthy, ready to go"

**Why this impresses:**
- Shows MCP connection works
- Shows Claude understands natural language → tool mapping
- Professional SOC workflow (analysts always check system health first)

📸 SCREENSHOT THIS RESULT



## SCENE 2: "THE INVESTIGATION" — Security Search
**What we're showing:** Analyst asks a security question, 
Claude queries Splunk automatically.

**Type this into Claude Desktop:**
I need to investigate potential brute force attacks.
Can you search Splunk for all failed authentication
events in the BOTS v3 dataset? Show me the top 10
source IPs with the most failed login attempts.

**Expected behavior:**
- Claude calls `splunk_search` tool
- Sends an SPL query like: 
  index=botsv3 sourcetype=* (fail* OR error* OR "invalid password") 
  | stats count by src_ip | sort -count | head 10
- Returns clean JSON with IP addresses and counts
- Claude analyzes and says something like "IP x.x.x.x has 
  the most failures — this is suspicious"

**Why this impresses:**
- Shows natural language → SPL query → results → analysis
- Shows the Backend Shield (clean JSON, no metadata junk)
- Shows real security value — finding attackers automatically

📸 SCREENSHOT THIS RESULT

---

## SCENE 3: "THE DEEP DIVE" — Targeted Search
**What we're showing:** Follow-up investigation on a 
suspicious finding.

**Type this into Claude Desktop:**
That's concerning. Can you search for all activity from
the most suspicious IP address you just found? I want to
see what else that IP was doing — any HTTP requests,
DNS queries, or other network activity. Limit to 10 events.

**Expected behavior:**
- Claude calls `splunk_search` again
- Uses the IP from Scene 2 in a new query
- Returns different types of events from that IP
- Claude provides analysis of the attacker's behavior

**Why this impresses:**
- Shows CONVERSATIONAL investigation (follow-up questions!)
- Claude remembers context from previous query
- Shows multi-step incident investigation in real-time

📸 SCREENSHOT THIS RESULT

---

## SCENE 4: "THE ALERT CHECK" — Monitoring Dashboard
**What we're showing:** Checking triggered security alerts.

**Type this into Claude Desktop:**
Now let me check our alert status. Can you pull all
the triggered alerts from Splunk? I want to see if
there are any critical or high severity alerts I
should prioritize.

**Expected behavior:**
- Claude calls `splunk_get_alerts` tool
- Returns list of fired/triggered alerts with severity
- Claude prioritizes them and suggests which to handle first

**If no alerts are configured, Claude should say:**
- "No triggered alerts found" — which is ALSO a valid result
- Shows the tool works even when there's nothing to report

**Why this impresses:**
- Shows the third tool works
- Shows alert monitoring capability
- Professional SOC workflow

📸 SCREENSHOT THIS RESULT

---

## SCENE 5: "THE FINALE" — The AI Advantage
**What we're showing:** Speed and intelligence comparison.

**Type this into Claude Desktop:**
Based on everything we've investigated today — the health
check, the brute force analysis, the suspicious IP deep
dive, and the alert status — can you give me a complete
security situation summary? What are the top threats I
should focus on, and what would you recommend as next steps?

**Expected behavior:**
- Claude does NOT call any tool (this is pure analysis)
- Summarizes ALL findings from Scenes 1-4
- Provides threat prioritization
- Recommends next steps (block IP, investigate user, etc.)
- THIS is the "wow moment" — the AI synthesizes everything

**Why this impresses:**
- Shows AI can be a REAL security co-pilot
- Full incident summary in seconds (vs 45-60 min manually)
- Actionable recommendations
- THIS is what we're selling — the future of SOC operations

📸 SCREENSHOT THIS RESULT — THIS IS YOUR MONEY SHOT

---

## DEMO TIMING
| Scene | Duration | Running Total |
|-------|----------|---------------|
| Setup verification | 2 min | 2 min |
| Scene 1: Health Check | 1 min | 3 min |
| Scene 2: Brute Force Search | 2 min | 5 min |
| Scene 3: Deep Dive | 2 min | 7 min |
| Scene 4: Alert Check | 1 min | 8 min |
| Scene 5: Summary | 2 min | 10 min |
| **TOTAL** | **~10 min** | |

---

## IF SOMETHING GOES WRONG DURING DEMO

| Problem | Quick Fix |
|---------|-----------|
| Claude doesn't call a tool | Rephrase: "Use the splunk_search tool to..." |
| Splunk connection error | Check if Splunk service is running |
| Empty results | Change time range or use simpler query |
| Claude crashes/freezes | Restart Claude Desktop, reconnect |
| JSON looks messy | Say "Can you format that as a clean table?" |

---

## BACKUP PROMPTS (if primary ones don't work well)

**Backup for Scene 2:**
Search index=botsv3 for HTTP requests with status
codes 400 or above. Show me the top 5 source IPs.

**Backup for Scene 3:**
Search index=botsv3 for all events from source IP
[paste IP here]. Show me the first 10 events with
source, destination, and action fields.
