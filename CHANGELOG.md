# Changelog

All notable changes to this project are documented here.

The first tagged release is 0.2.0; the 0.1.0 section reconstructs earlier project history from git.

## v0.2.3 - 2026-08-14

### Release engineering

- Raised the minimum Go version to 1.26.6 for the latest standard-library security fixes.
- Made release retries verify and reuse an already-published release, added release metadata consistency checks, and moved Go dependency-graph submission into a repository-owned workflow.
## 0.2.2 - 2026-08-02

### Fixed

- Fixed `daemon --config` discovery so scheduled routines use the configuration file selected on the command line.

### Documentation

- Reworked the README around installation, first controls, configuration, structured output, and linked reference material.

## 0.2.1 - 2026-07-17

### Highlights

- First release through the unified signed pipeline, with Developer ID signing, Apple notarization, independent draft verification, and publication only after every verifier passes.

### Release engineering

- Migrated release automation to the immutable `openclaw/release-workflows@v1.0.0-alpha.2` Go CLI pipeline, which freezes a protected green `main`, creates an annotated tag, builds the cross-platform matrix, signs and notarizes macOS binaries, verifies the credential-free draft, publishes it, and opens the next development cycle.
- Retained the former GoReleaser workflow as a documented manual-only legacy fallback, removing its tag trigger so a unified release cannot double-fire.
- Validated the release stack with Go 1.26.5, `actions/setup-go` 7.0.0, GoReleaser 2.17.0 and action 7.2.3, golangci-lint 2.12.2 and action 9.3.0, and pnpm 11.14.0.
- Refreshed `github.com/mattn/go-isatty` to 0.0.23 after a full direct and transitive Go dependency sweep.

## 0.2.0 - 2026-07-17

### Highlights

- Added side-aware household control so `status`, `on`, `off`, `temp`, and `away` can target `left`, `right`, `solo`, all discovered users, or an explicit user.
- Added `away on|off` for pausing and resuming pod conditioning during travel.
- Restored reliable authentication and data access with the current OAuth contract, bounded retries, transparent gzip handling, and resilient token caching.
- Modernized metrics and schedules around the working trends and Autopilot APIs while removing commands backed by retired endpoints.

### Controls and targeting

- Added `away on|off`, including household-wide `--both`, side targeting, and explicit user targeting. Thanks @omarshahine.
- Added side-aware household discovery and default all-target behavior for `status`, `on`, `off`, and `temp`. Thanks @igormf.
- Fixed side discovery while Away mode is active by using authoritative device mappings instead of the API's `away` sentinel. Thanks @omarshahine.
- Improved `status` output with discovered `left`, `right`, and `solo` targeting modes.

### Metrics and API compatibility

- Added timezone-aware trends telemetry, date-ranged presence queries, and side-aware sleep and presence handling. Thanks @igormf.
- Retargeted `schedule list` to the current Autopilot smart schedule and device-owner lookup to the supported device response. Thanks @omarshahine.
- Resolved `--timezone local` to an IANA timezone with a visible UTC fallback when local zone information is unavailable. Thanks @omarshahine and @dtrinh.
- Fixed `--date`, `--from`, and `--to` handling so sleep and metrics commands use their own Cobra flags. Thanks @omarshahine.
- Prevented travel subcommands from overwriting persistent Viper keys and renamed trip payload timezone input to `--trip-timezone`. Thanks @omarshahine.
- Removed retired schedule CRUD, `metrics summary`, and `metrics aggregate` commands in favor of working Autopilot and trends paths. Thanks @omarshahine.
- Removed unavailable `metrics insights` behavior and made retired metrics names fail with an unknown-command error. Thanks @Abhijay.

### Authentication and reliability

- Updated OAuth to the form-encoded token contract with configured app credentials, removed the broken legacy login fallback, restored transparent gzip decoding, and bounded 401/429 retries. Thanks @omarshahine, @petersentaylor, and @davidfencik.
- Reused cached OAuth tokens across household user IDs to avoid unnecessary password grants and rate-limit bursts. Thanks @omarshahine.
- Added file-backed token-cache fallback when the primary OS keychain cannot read or write tokens. Thanks @omarshahine.
- Improved token-cache lookup so cached authentication can work without an email when the cached account is unambiguous.

### Release engineering and quality

- Added GoReleaser archives for macOS, Linux, and Windows on amd64 and arm64, including manual tag backfills.
- Embedded the tagged version in release binaries and generated GitHub Release notes from the matching finalized changelog section.
- Added release-note and packaged-version smoke tests, current GoReleaser configuration, and tag validation that rejects `Unreleased` headings.
- Added an 85% core coverage gate and regression coverage for authentication, endpoint wrappers, targeting, presence, timezone resolution, daemon scheduling, output, and token caching.
- Updated the toolchain and direct dependencies to current stable releases, including Go 1.26.5, pnpm 11.13.1, `actions/setup-go` 7.0.0, GoReleaser 2.17.0, and golangci-lint 2.12.2.
- Synchronized the README and specification with the implemented command surface and current API limitations.

### Release notes

- Released with live-provider smoke waived by maintainer for this first tagged release.

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
