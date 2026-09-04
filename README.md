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

## Commands

| Area | Commands |
| --- | --- |
| Pod control | `status`, `on`, `off`, `temp`, `away` |
| Sleep data | `sleep`, `presence`, `metrics` |
| Pod features | `alarm`, `audio`, `base`, `device`, `schedule`, `tempmode` |
| Account and travel | `household`, `autopilot`, `travel` |

Run `eightctl <command> --help` for flags and subcommands. The [command specification](docs/spec.md#cli-surface-implemented) covers the complete surface and current provider constraints.

Use `eightctl away on --both` before a trip and `eightctl away off --both` to resume all household members, including when everyone is already away. If household user IDs cannot be resolved, the command reports an error.

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

Preview scheduled actions without changing the pod, then remove `--dry-run` when the schedule is ready:

```sh
eightctl daemon --config ~/.config/eightctl/config.yaml --dry-run
```

## Structured output

Commands that return rows support table, JSON, and CSV output. Use `--fields` to select columns:

```sh
eightctl status --output json
eightctl sleep day --date 2026-08-01 --output csv
eightctl status --fields side,name,mode,level
```

## Authentication and API behavior

`eightctl` authenticates against Eight Sleep's OAuth service and caches tokens in the operating system keyring, with a file-backed fallback. Reusing cached tokens reduces login traffic, but the provider can still return rate-limit errors.

The API is undocumented and cloud-only. The [project specification](docs/spec.md#reality-of-the-api) records the current contract, while [CHANGELOG.md](CHANGELOG.md) tracks endpoint removals and compatibility changes.

## Development

```sh
go build ./cmd/eightctl
go test ./...
make coverage
make lint
```

CI runs formatting, lint, tests, the core-package coverage gate, and a release-artifact smoke test.

## License

MIT. See [LICENSE](LICENSE).
