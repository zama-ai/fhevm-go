ifeq ($(shell uname), Darwin)
	CGO_LDFLAGS := -framework Security
endif

.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && CGO_LDFLAGS='$(CGO_LDFLAGS)' go build .

.PHONY: test
test: build-tfhe-rs-capi
	cd fhevm && CGO_LDFLAGS='$(CGO_LDFLAGS)' go test -v .

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && make build_c_api_experimental_deterministic_fft \
	&& cd target/release && rm -f *.dylib *.dll *.so

.PHONY: clean
clean:
	cd tfhe-rs && cargo clean
