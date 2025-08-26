.PHONY: lint test vendor clean

default: lint test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
