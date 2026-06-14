#!/usr/bin/env sh
set -eu

go mod tidy
go test ./...
go build -o cf-router .
