.PHONY: test vendor clean

default: test

test:
	go test -v -cover ./...

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
