# Tool #4 — splunk_create_alert: Build Notes

## Status: SKELETON COMPLETE ✅

## Confirmed Working Parameters
All of these work on Splunk Enterprise (Dev License):

- `name` — Alert name (we prefix with "MCP_")
- `search` — SPL query
- `is_scheduled` — "1" to enable scheduling
- `cron_schedule` — Cron expression (e.g. "*/10 * * * *")
- `alert_type` — "number of events"
- `alert_comparator` — "greater than"
- `alert_threshold` — String number (e.g. "0")
- `alert.severity` — "1" to "6" (mapped from INFO/LOW/MEDIUM/HIGH/CRITICAL/FATAL)
- `description` — Human-readable description
- `actions` — "logevent" (others to be researched)

## Naming Convention
All MCP-created alerts use prefix `MCP_`
Format: `MCP_<DESCRIPTION>`
Example: `MCP_BruteForce_FailedLogins50`

## Severity Mapping (per Splunk docs)
| Level    | Splunk Number |
|----------|---------------|
| INFO     | 1             |
| LOW      | 2             |
| MEDIUM   | 3             |
| HIGH     | 4             |
| CRITICAL | 5             |
| FATAL    | 6             |

## Pending Items (Awaiting Amin's Research)
- [ ] Additional `actions` types (email, webhook, script)
- [ ] Real-time alert support (alert_type variations)
- [ ] Throttling parameters
- [ ] 5 production-ready alert templates

## Integration with mcp_server.py (TODO Tomorrow)
- Import: `from tools.create_alert import create_splunk_alert`
- Register: `@mcp.tool()` decorator
- Test via Claude Desktop

## Test Results (Skeleton)
- ✅ Alert creation: Working
- ✅ Duplicate detection: Working
- ✅ Alert deletion: Working
- ✅ Validation: Working