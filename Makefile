ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TFHE_RS_FOLDER=${ROOT_DIR}/tfhe-rs/
CGO_CFLAGS="-I${TFHE_RS_FOLDER}/target/release/"
CGO_LDFLAGS="-L${TFHE_RS_FOLDER}/target/release/"

.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && CGO_CFLAGS=${CGO_CFLAGS} CGO_LDFLAGS=${CGO_LDFLAGS} go build .

.PHONY: test
test:
	cd fhevm && CGO_CFLAGS=${CGO_CFLAGS} CGO_LDFLAGS=${CGO_LDFLAGS} go test -v .

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && make build_c_api_experimental_deterministic_fft
