.PHONY: up down build ourcodex ourcodex-all install-ourcodex uninstall-ourcodex

# Docker
up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

# Build ourcodex client binary (current platform)
ourcodex:
	cd src/backend && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../dist/ourcodex ./cmd/cl/
	@echo "Built: dist/ourcodex"

# Build ourcodex for all common platforms
ourcodex-all:
	mkdir -p dist
	cd src/backend && \
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../dist/ourcodex-linux-amd64   ./cmd/cl/ && \
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../dist/ourcodex-linux-arm64   ./cmd/cl/ && \
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../dist/ourcodex-darwin-amd64  ./cmd/cl/ && \
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../dist/ourcodex-darwin-arm64  ./cmd/cl/ && \
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../dist/ourcodex-windows-amd64.exe ./cmd/cl/
	@echo "Built all platforms in dist/"

# Install ourcodex to /usr/local/bin
install-ourcodex: ourcodex
	install -m 755 dist/ourcodex /usr/local/bin/ourcodex
	@echo "Installed: /usr/local/bin/ourcodex"
	@echo "Run: ourcodex login <server_url>"

# Uninstall
uninstall-ourcodex:
	rm -f /usr/local/bin/ourcodex
	@echo "Uninstalled ourcodex"
