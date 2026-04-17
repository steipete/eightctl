# eightctl Specification (Dec 2025)

## Purpose
Eight Sleep Pod power/control + data-export CLI, written in Go. Targets macOS/Linux users who want a dependable terminal tool (incl. daemon) for pod automations, metrics export, and feature toggles that the mobile app exposes but the vendor does not document.

## Reality of the API
- Eight Sleep does **not** publish a stable public API; we rely on the same cloud endpoints the mobile apps use.
- Default OAuth client creds extracted from Android APK 7.39.17:
  - `client_id`: `0894c7f33bb94800a03f1f4df13a4f38`
  - `client_secret`: `f0954a3ed5763ba3d06834c73731a32f15f168f47d4f164751275def86db0c76`
- Auth flow: OAuth password grant at `https://auth-api.8slp.net/v1/tokens` (form-urlencoded).
- Throttling: 429s observed; client retries with small delay and re-auths on 401.

## Configuration & Auth
- Config file: `~/.config/eightctl/config.yaml`; env prefix `EIGHTCTL_`; flags override env override file.
- Fields: `email`, `password`, optional `user_id`, `client_id`, `client_secret`, `timezone`, `output`, `fields`, `verbose`.
- Permissions check warns if config is more permissive than `0600`.

## CLI Surface (implemented)
Core: `on`, `off`, `temp <level>`, `status`, `whoami`, `version`.

Schedules & daemon:
- `schedule list|create|update|delete` (cloud temperature schedules)
- `daemon` (YAML-based scheduler with PID guard, dry-run, timezone override, optional state sync)

Alarms:
- `alarm list|create|update|delete`
- `alarm snooze|dismiss|dismiss-all|vibration-test`

Temperature modes & events:
- `tempmode nap on|off|extend|status`
- `tempmode hotflash on|off|status`
- `tempmode events --from --to` (temperature event history)

Audio:
- `audio tracks|categories|state|play|pause|seek|volume|pair|next`

Adjustable base:
- `base info|angle|presets|preset-run|vibration-test`

Device & maintenance:
- `device info|peripherals|owner|warranty|online|priming-tasks|priming-schedule`

Metrics & insights:
- `metrics trends --from --to`
- `metrics intervals --id`
- `metrics summary`
- `metrics aggregate`
- `metrics insights`
- `sleep day --date`, `sleep range --from --to`
- `presence [--from --to]`

Autopilot:
- `autopilot details|history|recap`
- `autopilot set-level-suggestions --enabled`
- `autopilot set-snore-mitigation --enabled`

Travel:
- `travel trips|create-trip|delete-trip`
- `travel plans --trip`
- `travel tasks --plan`
- `travel airport-search --query`
- `travel flight-status --flight`

Household:
- `household summary|schedule|current-set|invitations|devices|users|guests`

Audio/temperature data helpers:
- `tracks`, `feats` remain for backward compatibility.

## Output & UX
- Output formats: table (default), json, csv via `--output`; `--fields` to select columns.
- Logs via charmbracelet/log; `--verbose` for debug; `--quiet` hides config notice.
- `status` should prefer discovered household targets when available and display `left` / `right` or inferred `solo`.
- `on`, `off`, and `temp` should default to all discovered household targets unless narrowed with `--side` or `--target-user-id`.
- `temp` accepts negative positional levels such as `temp -40` without requiring `--`.

## Daemon Behavior
- Reads YAML schedule (time, action on|off|temp, temperature with unit), minute tick, executes once per day, PID guard, SIGINT/SIGTERM graceful stop.
- Optional state sync compares expected schedule state vs device and reconciles.

## Testing & Quality Gates
- `go test ./...` (fast compile checks) — run before handoff.
- Formatting via `gofumpt`; prefer `staticcheck`/additional linting later as needed.
- Live checks: `eightctl status`, `metrics summary`, `tempmode nap status` with test creds to validate auth + userId resolution.

## Prior Work (references)
- Go CLI `clim8`: https://github.com/blacktop/clim8
- MCP server (Node/TS): https://github.com/elizabethtrykin/8sleep-mcp
- Python library `pyEight`: https://github.com/mezz64/pyEight
- Home Assistant integrations: https://github.com/lukas-clarke/eight_sleep and https://github.com/grantnedwards/eight-sleep
- Homebridge plugin: https://github.com/nfarina/homebridge-eightsleep
- Additional notes on API stability: https://www.reddit.com/r/EightSleep/comments/15ybfrv/eight_sleep_removed_smart_home_capabilities/
