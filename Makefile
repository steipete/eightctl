# Local binary directory. Override for a different location:
#   make install PREFIX=/usr/local/bin
PREFIX ?= $(HOME)/.local/bin

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

# Local development only; release signing is handled by GoReleaser.
# Re-sign the installed macOS executable so its signature matches its bytes
# after replacement. This does not preserve existing Keychain authorization.
install: build
	install -d "$(PREFIX)"
	install -m 0755 ./eightctl "$(PREFIX)/eightctl"
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign --force --sign - "$(PREFIX)/eightctl" && \
		codesign --verify "$(PREFIX)/eightctl" && \
		echo "installed and signed: $(PREFIX)/eightctl"; \
	else \
		echo "installed: $(PREFIX)/eightctl"; \
	fi
