#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
(cd web && npm ci && npm run build)
go mod download
go vet ./...
mkdir -p bin
go build -trimpath -ldflags='-s -w' -o bin/rewind ./cmd/rewind
printf 'Built bin/rewind\n'
