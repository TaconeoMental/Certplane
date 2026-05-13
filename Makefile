.PHONY: all build broker agent test test-race vet fmt fmt-check tidy-check lint clean

BIN_DIR := bin

BROKER_BIN := $(BIN_DIR)/certplane-broker
AGENT_BIN := $(BIN_DIR)/certplane-agent

GOFLAGS :=
LDFLAGS := -s -w

all: build

build: broker agent

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

broker: $(BIN_DIR)
	go build $(GOFLAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BROKER_BIN) ./cmd/broker

agent: $(BIN_DIR)
	go build $(GOFLAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(AGENT_BIN) ./cmd/agent

test:
	go test ./...

test-race:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt required:" && gofmt -l . && exit 1)

tidy-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

lint:
	golangci-lint run

clean:
	rm -rf $(BIN_DIR) coverage.out
