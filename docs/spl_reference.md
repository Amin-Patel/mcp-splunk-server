# SPL Quick Reference — MCP-Splunk Project

## Author: Sayyed Abuzar (Team Lead)
## Date: Week 1, Day 3

---

## Basic Commands

| Command | What It Does | Example |
|---------|-------------|---------|
| `search` | Find events | `index=_internal ERROR` |
| `stats` | Aggregate data | `\| stats count by src_ip` |
| `where` | Filter results | `\| where count > 10` |
| `table` | Select columns | `\| table src_ip, count` |
| `sort` | Order results | `\| sort - count` |
| `head` | First N results | `\| head 10` |
| `top` | Most common values | `\| top limit=5 sourcetype` |
| `timechart` | Time-based chart | `\| timechart span=1h count` |
| `eval` | Create new field | `\| eval status=if(count>10,"HIGH","LOW")` |
| `dc()` | Distinct count | `\| stats dc(src_ip)` |

## Security Query Patterns

### Find errors by severity
index=_internal log_level=ERROR
| stats count by component
| sort - count

### Detect spikes (brute force pattern)
index=_internal
| timechart span=30m count
| where count > threshold

### System overview dashboard
index=_internal
| stats count, dc(source), dc(sourcetype), dc(host)

## Notes
- `dc()` = distinct count (like pandas nunique)
- `eval` = create calculated field (like pandas apply)
- `-` before field in sort = descending order
- `span=1h` in timechart = bucket size of 1 hour
## Advanced Security Queries (Day 4)

### Multi-Condition Threat Hunting
index=_internal
| eval severity=case(
log_level=="ERROR", "CRITICAL",
log_level=="WARN", "WARNING",
true(), "OTHER"
)
| stats count by severity, component
| where severity IN ("CRITICAL", "WARNING")
| sort - count
**Key commands:** `eval case()`, `IN()`, multi-field grouping

### Anomaly Detection (Statistical)
index=_internal
| stats count as event_count by source
| eventstats avg(event_count) as avg_events, stdev(event_count) as stdev_events
| eval threshold=avg_events + (2 * stdev_events)
| eval is_anomaly=if(event_count > threshold, "ANOMALY", "NORMAL")
| where is_anomaly="ANOMALY"
**Key commands:** `eventstats`, `stdev()`, statistical thresholds

### Investigation Timeline
index=_internal
| where log_level IN ("ERROR", "WARN")
| sort _time
| table _time, log_level, component, message
| head 20
**Key commands:** `sort _time` for chronological order, `table` for clean output

## Week 2 — BOTS v3 Real Security Data Queries

### Dataset Info
- Index: botsv3
- Total events: 2,083,056
- Always use: earliest=0 (data is from 2018)

### Exploration Queries
All sourcetypes
index=botsv3 earliest=0 | stats count by sourcetype | sort - count

Time range
index=botsv3 earliest=0 | stats min(_time) as first, max(_time) as last

All hosts
index=botsv3 earliest=0 | stats count by host | sort - count

### Security Detection Queries
Windows login failures (brute force)
index=botsv3 earliest=0 sourcetype=wineventlog EventCode=4625
| stats count by src_ip, user | sort - count

DNS queries (tunneling detection)
index=botsv3 earliest=0 sourcetype=stream:dns
| stats count by query | sort - count

HTTP traffic analysis (web attacks)
index=botsv3 earliest=0 sourcetype=stream:http
| stats count by http_method, status, uri_path | sort - count

## Week 2 Day 2 — Attack Detection Results

### Confirmed Attacks in BOTS v3
| Attack | IP | Evidence | MITRE |
|--------|-------|----------|-------|
| XSS Web Attack | 61.75.35.114 | Malicious scripts in HTTP | T1059.007 |
| Port Scanning | 192.168.8.103 | 35 unique ports scanned | T1046 |
| Data Exfiltration | 172.16.133.131 | 126 MB sent outbound | T1041 |

### Negative Findings
| Attack | Result | Notes |
|--------|--------|-------|
| Brute Force | Only 3 failed logins | No active attack |
| DNS Tunneling | Long domains but CDN/cloud | Suspicious AWS domains noted |

### Key Learnings
- Field names vary: `name{}` for DNS, `Source_Network_Address` for Windows
- Multi-value fields need `mvexpand` command
- Not every attack type exists in every dataset
- Sourcetype matters: `wineventlog:security` not `wineventlog`