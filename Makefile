ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TFHE_RS_FOLDER=${ROOT_DIR}/tfhe-rs/

.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && CGO_CFLAGS="-I${TFHE_RS_FOLDER}/target/release/ -L${TFHE_RS_FOLDER}/target/release/" go build .

.PHONY: test
test:
	cd fhevm && go test -v .

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && make build_c_api_experimental_deterministic_fft
