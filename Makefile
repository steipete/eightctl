# Local install prefix. Override for a different location:
#   make install PREFIX=/usr/local/bin
PREFIX ?= /opt/homebrew/bin

.PHONY: fmt lint test coverage build install

fmt:
	go tool mvdan.cc/gofumpt -w ./

lint:
	golangci-lint run ./...

test:
	go test ./...

coverage:
	go test -coverpkg=./internal/client,./internal/config,./internal/daemon,./internal/output,./internal/tokencache ./internal/client ./internal/config ./internal/daemon ./internal/output ./internal/tokencache -coverprofile=coverage.out
	go tool cover -func=coverage.out | awk '/^total:/ {gsub("%", "", $$3); print "core coverage: " $$3 "%"; exit !($$3 >= 85.0)}'

build:
	go build -o ./eightctl ./cmd/eightctl

# Local development install. NOT the release path -- releases are built by
# GoReleaser (.goreleaser.yaml) from a tag.
#
# The ad-hoc re-sign is required on macOS, not hygiene (it is skipped
# elsewhere). macOS caches a binary's code
# signature against its path, so overwriting the file in place leaves the
# cached CDHash describing content that no longer exists and AMFI SIGKILLs
# every invocation afterwards. It presents as the binary producing no output
# at all and exiting 137 -- even `eightctl --help` -- which reads like a
# hang or a network fault rather than a signing problem. Re-signing
# refreshes the cache.
#
# Expect one more consequence: installing changes the binary's identity, so
# the cached auth token in the Keychain is still ACL'd to the previous one
# and the next command blocks on a Keychain prompt. Either answer "Always
# Allow" once, or run `eightctl logout` -- with credentials in the config
# file that clears the stale item and the next call re-authenticates with no
# prompt at all, which is the quicker path on a headless machine where
# nobody is watching for a dialog.
install: build
	install -m 0755 ./eightctl "$(PREFIX)/eightctl"
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign --force --sign - "$(PREFIX)/eightctl" && \
		codesign --verify "$(PREFIX)/eightctl" && \
		echo "installed and signed: $(PREFIX)/eightctl"; \
	else \
		echo "installed: $(PREFIX)/eightctl"; \
	fi
