.PHONY: build test lint up down bootstrap run backfill check reset

build:
	go build ./...

test:
	go test ./...

lint:
	gofmt -l .
	go vet ./...

up:
	docker compose up -d

down:
	docker compose down

bootstrap:
	go run ./cmd/wiretapd bootstrap

run:
	go run ./cmd/wiretapd run

backfill:
	go run ./cmd/wiretapd backfill

check:
	go run ./cmd/wiretapd check

# Full stack teardown, including every named volume (Langfuse's project
# data, Elasticsearch's index, all of it) -- NOT the same thing as
# RUNBOOK.md's "Resetting poisoned trace data" procedure, which is
# surgical and deliberately manual. This is docker compose down -v; know
# what you're giving up (see RUNBOOK.md's own warning table) before
# running it.
reset:
	docker compose down -v
