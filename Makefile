.PHONY: build
build:
	cd fhevm && go build .

.PHONY: test
test:
	cd fhevm && go test -v .
