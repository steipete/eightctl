# Changelog

All notable changes to this project are documented here.

This project has not cut tagged releases yet. The entries below reconstruct the
release history from git.

## 0.2.0 - Unreleased

### Added

- Away mode via `away on|off`.
- Side-aware household targeting for `status`, `on`, `off`, `temp`, and `away`
  with `--side` and `--target-user-id`.
- Metrics trends telemetry and side-aware presence/sleep data handling.
- GoReleaser workflow and Linux arm64 build target.
- Core coverage gate with regression tests for client endpoint wrappers,
  configuration, daemon scheduling, output formatting, and token cache helpers.

### Changed

- OAuth now uses the current token endpoint contract with
  `application/x-www-form-urlencoded` bodies.
- API calls were updated for current Eight Sleep cloud endpoints.
- `schedule list` now surfaces the Autopilot smart schedule because the older
  temperature schedule CRUD endpoints are no longer available.
- `--timezone local` now resolves to an IANA timezone before making API
  requests, with UTC fallback when local zoneinfo is unavailable.
- Documentation now reflects removed API-backed behavior, timezone handling,
  and the current command surface.
- Release automation now uses `.goreleaser.yaml`, supports tag backfills, and
  includes a Linux arm64 target.
- Release packaging configuration now uses the current GoReleaser archive fields.
- Lint configuration was prepared for golangci-lint v2.
- Go module now targets Go 1.26.4 and tracks `gofumpt` with the Go tool directive.
- Dependencies and CI tooling were updated to current stable versions, including pnpm 11.

### Fixed

- Release archives now report the tagged version from `eightctl version`, include the matching changelog section in GitHub Release notes, and use a pinned GoReleaser version.
- Reused cached OAuth tokens across household user IDs.
- Resolved away-mode targeting correctly for left/right/solo household sides.
- Added keychain fallback behavior for cached token lookup.
- Fixed `--date`, `--from`, and `--to` handling by reading Cobra flags directly.
- Prevented travel subcommands from clobbering persistent Viper keys.

### Removed

- Removed unavailable `metrics summary` and `metrics aggregate` behavior after
  Eight Sleep endpoint changes; use `metrics trends` instead.

### Tests

- Added regression coverage for OAuth request encoding, side-aware targeting,
  presence parsing, timezone resolution, and token cache lookup.

## 0.1.0 - 2025-12-12

### Added

- Initial Go CLI for Eight Sleep Pods: power, temperature, status, whoami, and
  version commands.
- Alarm, audio, adjustable base, device, Autopilot, presence, sleep, household,
  travel, temperature mode, and daemon command groups.
- Table, JSON, and CSV output, with `--fields` column selection.
- YAML-driven daemon scheduler with dry-run support and PID guarding.
- Travel create/update flows, audio favorites, household listing commands, and
  schedule next-state support.
- `logout` command for clearing cached credentials.
- OS keyring token caching, including cached lookup without email when the
  cached account is unambiguous.
- Tests, linting, CI, README command coverage, and package-manager convenience
  scripts.

### Changed

- HTTP headers now more closely match the Android app to reduce throttling.
- README gained the current project tagline, WIP/API-rate-limit notice, and
  broader feature documentation.

### Fixed

- Fixed verbose mode so it sets the global log level.
- Added auth failure logging for response headers/body to make API failures
  diagnosable.
- Ran gofumpt formatting and tightened CI format checks.

### Security

- Bumped `github.com/dvsekhvalnov/jose2go`.
