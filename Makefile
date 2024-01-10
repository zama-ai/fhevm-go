.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && go build .

.PHONY: test
test: build-tfhe-rs-capi
	cd fhevm && go test -v .

.PHONY: benchmarks
benchmarks: build-tfhe-rs-capi
	cd fhevm && go test -count=1 -v . -run Benchmarks

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && RUSTFLAGS="" make build_c_api_experimental_deterministic_fft \
	&& cd target/release && rm -f *.dylib *.dll *.so

.PHONY: clean
clean:
	cd tfhe-rs && cargo clean
