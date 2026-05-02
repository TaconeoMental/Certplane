.PHONY: build broker agent test lint clean

build: broker agent

broker:
	go build -o bin/certplane-broker ./cmd/broker

agent:
	go build -o bin/certplane-agent ./cmd/agent

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/ coverage.out
