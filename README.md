# eightctl 🛏️ — Control your sleep, from the terminal

[![CI](https://img.shields.io/github/actions/workflow/status/steipete/eightctl/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/steipete/eightctl/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/steipete/eightctl?style=flat-square)](https://github.com/steipete/eightctl/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/steipete/eightctl?style=flat-square)](https://go.dev/)
[![License](https://img.shields.io/github/license/steipete/eightctl?style=flat-square)](LICENSE)
[![Homebrew](https://img.shields.io/badge/Homebrew-steipete%2Ftap-orange?style=flat-square)](https://github.com/steipete/homebrew-tap)

`eightctl` is an unofficial CLI for controlling Eight Sleep Pods and exporting sleep data. It is for people who want pod controls and metrics from a terminal or script.

> [!IMPORTANT]
> Eight Sleep does not publish a stable public API. `eightctl` uses the company's cloud endpoints, so provider changes and rate limits can interrupt commands; it does not provide local or Bluetooth control.

## Install

With [Homebrew](https://brew.sh/):

```sh
brew install steipete/tap/eightctl
```

Prebuilt archives for macOS, Linux, and Windows on amd64 and arm64 are available from the [latest GitHub release](https://github.com/steipete/eightctl/releases/latest).

Check the installed version with `eightctl --version` or `eightctl version`.

To build and install from source, use Go 1.26.7 or newer:

```sh
go install github.com/steipete/eightctl/cmd/eightctl@latest
```

## Quick start

Set your Eight Sleep account credentials, then inspect and control the pod:

```sh
export EIGHTCTL_EMAIL="you@example.com"
export EIGHTCTL_PASSWORD="your-password"

eightctl status
eightctl temp 20
eightctl temp -40 --side right
```

`status`, `on`, `off`, and `temp` act on all discovered household sides unless you select one with `--side left|right|solo` or `--target-user-id <id>`.

Discovery fails explicitly if a household user response omits its ID or returns a different ID; commands do not substitute the authenticated user's side for a malformed target. `whoami` reuses the configured or cached user ID, resolving it from the API only when needed.

`eightctl --user-id <id> whoami` can display that configured ID offline without account credentials.

## Commands

| Area | Commands |
| --- | --- |
| Pod control | `status`, `on`, `off`, `temp`, `away` |
| Sleep data | `sleep`, `presence`, `metrics` |
| Pod features | `alarm`, `audio`, `base`, `device`, `schedule`, `tempmode` |
| Account and travel | `household`, `autopilot`, `travel` |

Run `eightctl <command> --help` for flags and subcommands. The [command specification](docs/spec.md#cli-surface-implemented) covers the complete surface and current provider constraints.

Options belong to the selected subcommand: for example, `eightctl alarm create --time 07:30 --days 1,2,3,4,5` and `eightctl autopilot level-suggestions --enabled=false` use the values passed to those commands.

Use `eightctl away on --both` before a trip and `eightctl away off --both` to resume all household members, including when everyone is already away. If household user IDs cannot be resolved, the command reports an error.

`eightctl away status` reads the cloud-reported state for all discovered household sides; use `--side` or `--target-user-id` to select one person. In contrast, `away on|off` without targeting flags changes only the authenticated user's side. The cloud is eventually consistent: readback may show the previous state after a write and does not immediately confirm that a change took effect.

## Configuration

Flags take precedence over `EIGHTCTL_*` environment variables, which take precedence over `~/.config/eightctl/config.yaml`:

```yaml
email: "you@example.com"
password: "your-password"
timezone: "America/New_York"
output: "table"
schedule:
  - time: "22:30"
    action: "temp"
    temperature: "-20"
```

Keep the file readable only by your account with `chmod 600 ~/.config/eightctl/config.yaml`. The optional `user_id` is resolved after authentication, and the public app OAuth client is used unless `client_id` and `client_secret` are set.

Schedule times and dates use the configured `timezone`, even when it differs from the host timezone.

Default sleep/presence dates also use that timezone. Presence queries default to yesterday through today as calendar dates, including across daylight-saving transitions. Standalone binaries include IANA timezone data.

An absent default config file is optional. An explicitly selected missing file or malformed YAML is an error. Temperature values must be complete integer levels from -100 to 100, or finite numbers ending in `F` or `C`; persistent flags also work after `temp`, including with negative values.

Preview scheduled actions without changing the pod, then remove `--dry-run` when the schedule is ready:

Dry-run needs no account credentials. The daemon validates every schedule entry before starting, creates its PID file exclusively, and cancels active requests on shutdown. If a previous process was killed without cleanup, remove its stale PID file only after confirming that daemon is no longer running.

```sh
eightctl daemon --config ~/.config/eightctl/config.yaml --dry-run
```

## Structured output

Commands that return rows support table, JSON, and CSV output. Use `--fields` to select columns:

Selected fields also define column order in table and CSV output. For commands returning a nested payload, selection applies to the top-level row fields.

```sh
eightctl status --output json
eightctl sleep day --date 2026-08-01 --output csv
eightctl status --fields side,name,mode,level
```

## Authentication and API behavior

`eightctl` authenticates against Eight Sleep's OAuth service and caches tokens between commands. Published macOS binaries are built without CGO and use the file-backed cache at `~/.config/eightctl/keyring`. CGO-enabled macOS source builds prefer Keychain; other platforms use an available operating system keyring, with a file-backed fallback. Reusing cached tokens reduces login traffic, but the provider can still return rate-limit errors.

`eightctl logout` removes the selected account's local cached token from reachable stores. It returns an error if a reachable store refuses deletion, even when another store clears successfully. An unavailable store remains tolerated if another opens. Logout does not revoke tokens at Eight Sleep; an already-issued token remains valid at the service until it expires.

When no email is configured, logout resolves a single cached account across reachable stores. If more than one account matches, it asks for `--email` and leaves the stores untouched. Legacy and current cache keys for the same account are removed together.

The API is undocumented and cloud-only. The [project specification](docs/spec.md#reality-of-the-api) records the current contract, while [CHANGELOG.md](CHANGELOG.md) tracks endpoint removals and compatibility changes.

## Development

The preferred build toolchain is Go 1.26.8, selected by `go.mod`; Go 1.26.7 remains the supported minimum and is tested in CI. The optional package scripts use pnpm 12.4.1 with Node.js 24 or newer.

```sh
make build
go test ./...
make coverage
make lint
```

`make build` writes `./eightctl`. To install a local development build, run
`make install`; it creates `~/.local/bin` if needed. Add that directory to your
`PATH`, or select another binary directory with
`make install PREFIX=/usr/local/bin`.

On macOS, installation ad-hoc signs and verifies the installed executable to
avoid stale-signature launch failures after replacement. A rebuilt executable
can still trigger a Keychain authorization prompt when accessing cached tokens;
this install helper does not make authenticated commands prompt-free on
unattended hosts. Published releases use the separate signed release pipeline.

CI runs formatting, lint (including staticcheck and unused-code checks), race-enabled tests, the core-package coverage gate, and a release-artifact smoke test. Separate jobs test the minimum Go 1.26.7 and current Go 1.27.1 toolchains without automatic toolchain upgrades.

## License

MIT. See [LICENSE](LICENSE).
