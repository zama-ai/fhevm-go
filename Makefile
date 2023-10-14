ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TFHE_RS_FOLDER=${ROOT_DIR}/tfhe-rs/
TFHE_BUILD_DIR=${TFHE_RS_FOLDER}/target/release/
CGO_CFLAGS="-I${TFHE_BUILD_DIR}"
CGO_LDFLAGS="-L${TFHE_BUILD_DIR}"

.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && CGO_CFLAGS=${CGO_CFLAGS} CGO_LDFLAGS=${CGO_LDFLAGS} go build .

.PHONY: test
test: build-tfhe-rs-capi
	cd fhevm && CGO_CFLAGS=${CGO_CFLAGS} CGO_LDFLAGS=${CGO_LDFLAGS} go test -v .

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && make build_c_api_experimental_deterministic_fft
