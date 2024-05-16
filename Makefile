.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && go build .

.PHONY: test
test: build-tfhe-rs-capi
	cd fhevm && TFHE_EXECUTOR_CONTRACT_ADDRESS=0x05fD9B5EFE0a996095f42Ed7e77c390810CF660c go test -v ./...

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && RUSTFLAGS="" make build_c_api_experimental_deterministic_fft \
	&& cd target/release && rm -f *.dylib *.dll *.so

.PHONY: clean
clean:
	cd tfhe-rs && cargo clean
