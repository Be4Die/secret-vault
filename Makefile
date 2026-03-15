.PHONY: all build run clean templ tailwind dev setup test test-unit test-integration test-coverage test-all

APP_NAME := secret-vault
BUILD_DIR := ./bin

all: build

setup:
	go install github.com/a-h/templ/cmd/templ@latest
	go mod download

templ:
	templ generate

build: templ
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/server

run: build
	$(BUILD_DIR)/$(APP_NAME)

dev: templ
	go run ./cmd/server

clean:
	rm -rf $(BUILD_DIR)
	find . -name "*_templ.go" -delete
	rm -f coverage.out coverage.html

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

test-unit:
	go test ./... -count=1 -short

test-integration:
	go test ./... -tags=integration -count=1 -v

test-all: test-unit test-integration

test: test-unit

test-coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration-coverage:
	go test ./... -tags=integration -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-race:
	go test ./... -race -count=1

test-integration-race:
	go test ./... -tags=integration -race -count=1 -v

fmt:
	go fmt ./...

vet:
	go vet ./...
