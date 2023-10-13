.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && go build .

.PHONY: test
test: build-tfhe-rs-capi
	cd fhevm && go test -v .

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && make build_c_api_experimental_deterministic_fft

.PHONY: clean
clean:
	cd tfhe-rs && cargo clean
