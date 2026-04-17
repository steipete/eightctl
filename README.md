# 🛏️ eightctl — Control your sleep, from the terminal

A modern Go CLI for Eight Sleep Pods. Control power/temperature, alarms, schedules, audio, base, autopilot, travel, household, and export sleep metrics. Includes a daemon for scheduled routines.

> Eight Sleep does **not** publish a stable public API. `eightctl` talks to the same undocumented cloud endpoints the mobile apps use. Default OAuth client creds are baked in (from Android APK 7.39.17), so typically you only supply email + password.
> **Status:** WIP. The code paths are implemented, but live verification is currently blocked by Eight Sleep API rate limiting on the test account.

## Quickstart
```bash
# build + install
GO111MODULE=on go install github.com/steipete/eightctl/cmd/eightctl@latest

# create config (optional; flags/env also work)
mkdir -p ~/.config/eightctl
cat > ~/.config/eightctl/config.yaml <<'CFG'
email: "you@example.com"
password: "your-password"
# user_id: "optional"               # auto-resolved via /users/me
# timezone: "America/New_York"      # defaults to local
# client_id / client_secret optional # defaults to app creds
CFG
chmod 600 ~/.config/eightctl/config.yaml

# check pod state
EIGHTCTL_EMAIL=you@example.com EIGHTCTL_PASSWORD=your-password eightctl status

# set temperature level (-100..100); without --side, applies to all discovered sides/users
eightctl temp 20

# target a specific side when the household is split
eightctl temp -40 --side right
eightctl on --side left

# run daemon with your YAML schedule (see docs/example-schedule.yaml)
eightctl daemon --dry-run
```

## Command Surface
- **Power & temp:** `on`, `off`, `temp <level>`, `status`
- **Away mode:** `away on|off`
- **Schedules & daemon:** `schedule list` (Autopilot/smart schedule), `daemon`
- **Alarms:** `alarm list|create|update|delete|snooze|dismiss|dismiss-all|vibration-test`
- **Temperature modes:** `tempmode nap on|off|extend|status`, `tempmode hotflash on|off|status`, `tempmode events`
- **Audio:** `audio tracks|categories|state|play|pause|seek|volume|pair|next`, `audio favorites list|add|remove`
- **Base:** `base info|angle|presets|preset-run|vibration-test`
- **Device:** `device info|peripherals|owner|warranty|online|priming-tasks|priming-schedule`
- **Metrics & insights:** `sleep day|range`, `presence [--from --to]`, `metrics trends|intervals|insights`
- **Autopilot:** `autopilot details|history|recap`, `autopilot set-level-suggestions`, `autopilot set-snore-mitigation`
- **Travel:** `travel trips|create-trip|delete-trip|plans|create-plan|update-plan|tasks|airport-search|flight-status`
- **Household:** `household summary|schedule|current-set|invitations|devices|users|guests`
- **Misc:** `tracks`, `feats`, `whoami`, `version`

Use `--output table|json|csv` and `--fields field1,field2` to shape output. `--verbose` enables debug logs; `--quiet` hides the config banner.

## Household Targeting
- `status` shows discovered household targets by default when available, including `left` / `right` or inferred `solo`.
- `on`, `off`, and `temp` apply to all discovered household targets by default.
- Use `--side left|right|solo` to target one household side.
- Use `--target-user-id <id>` when you want to address a specific discovered user directly.
- For split households, `eightctl status --output json` is the quickest way to inspect available sides and user IDs.

## Configuration
Priority: flags > env vars (`EIGHTCTL_*`) > config file.

Key fields: `email`, `password`, optional `user_id`, `client_id`, `client_secret`, `timezone`, `output`, `fields`, `verbose`. The client auto-resolves `user_id` and `device_id` after authentication. Config file permissions are checked (warn if >0600).

## Tooling
- Make: `make fmt` (gofumpt), `make lint` (golangci-lint), `make test` (go test ./...)
- CI: `.github/workflows/ci.yml` runs format, lint, tests.
- pnpm scripts (optional): `pnpm eightctl|start|build|lint|format|test` (see package.json).

## Known API realities
- The API is undocumented and rate-limited; repeated logins can return 429. The client now mimics Android app headers and reuses tokens to reduce throttling, but cooldowns may still apply.
- Authentication uses the OAuth2 password grant against `auth-api.8slp.net/v1/tokens` with `application/x-www-form-urlencoded` bodies. The legacy `/login` JSON endpoint is no longer called.
- HTTPS only; no local/Bluetooth control exposed here.
- Eight Sleep retired the temperature-schedules/routines CRUD API; `schedule list` now surfaces the Autopilot (smart) schedule from the `smart` subfield of `app-api.8slp.net/v1/users/:id/temperature`. `metrics summary` / `metrics aggregate` were removed because the underlying endpoints no longer exist — use `metrics trends` instead.
- The `tz` query param rejects the literal strings `local` / `Local`. The client resolves `--timezone local` (the default) to a real IANA zone, falling back to `UTC` with a warning when the system has no zoneinfo.

## Prior Work / References
- Go CLI `clim8`: https://github.com/blacktop/clim8
- MCP server (Node/TS): https://github.com/elizabethtrykin/8sleep-mcp
- Python library `pyEight`: https://github.com/mezz64/pyEight
- Home Assistant integrations: https://github.com/lukas-clarke/eight_sleep and https://github.com/grantnedwards/eight-sleep
- Homebridge plugin: https://github.com/nfarina/homebridge-eightsleep
- Background on the unofficial API and feature removals: https://www.reddit.com/r/EightSleep/comments/15ybfrv/eight_sleep_removed_smart_home_capabilities/
