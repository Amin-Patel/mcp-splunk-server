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
