package tfhe

/*
#cgo linux CFLAGS: -O3 -I../../tfhe-rs/target/release -I../../tfhe-rs/target/release/deps
#cgo linux LDFLAGS: -L../../tfhe-rs/target/release -l:libtfhe.a -L../../tfhe-rs/target/release/deps -l:libtfhe_c_api_dynamic_buffer.a -lm
#cgo darwin CFLAGS: -O3 -I../../tfhe-rs/target/release -I../../tfhe-rs/target/release/deps
#cgo darwin LDFLAGS: -framework Security -L../../tfhe-rs/target/release -ltfhe -L../../tfhe-rs/target/release/deps -ltfhe_c_api_dynamic_buffer -lm

#include "tfhe_wrappers.h"

*/
import "C"

import (
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"unsafe"
)

func toDynamicBufferView(in []byte) C.DynamicBufferView {
	return C.DynamicBufferView{
		pointer: (*C.uint8_t)(unsafe.Pointer(&in[0])),
		length:  (C.size_t)(len(in)),
	}
}

func serialize(ptr unsafe.Pointer, t FheUintType) ([]byte, error) {
	out := &C.DynamicBuffer{}
	var ret C.int
	switch t {
	case FheBool:
		ret = C.serialize_fhe_bool(ptr, out)
	case FheUint4:
		ret = C.serialize_fhe_uint4(ptr, out)
	case FheUint8:
		ret = C.serialize_fhe_uint8(ptr, out)
	case FheUint16:
		ret = C.serialize_fhe_uint16(ptr, out)
	case FheUint32:
		ret = C.serialize_fhe_uint32(ptr, out)
	case FheUint64:
		ret = C.serialize_fhe_uint64(ptr, out)
	case FheUint160:
		ret = C.serialize_fhe_uint160(ptr, out)
	default:
		panic("serialize: unexpected ciphertext type")
	}
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize a ciphertext")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser, nil
}

func SerializePublicKey() ([]byte, error) {
	if pks == nil {
		return nil, errors.New("serialize: no public key available")
	}
	out := &C.DynamicBuffer{}
	ret := C.serialize_compact_public_key(pks, out)
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize public key")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser, nil
}

func EncryptAndSerializeCompact(value uint64, fheUintType FheUintType) []byte {
	out := &C.DynamicBuffer{}
	switch fheUintType {
	case FheBool:
		val := false
		if value == 1 {
			val = true
		}
		C.public_key_encrypt_and_serialize_fhe_bool_list(pks, C.bool(val), out)
	case FheUint4:
		C.public_key_encrypt_and_serialize_fhe_uint4_list(pks, C.uint8_t(value), out)
	case FheUint8:
		C.public_key_encrypt_and_serialize_fhe_uint8_list(pks, C.uint8_t(value), out)
	case FheUint16:
		C.public_key_encrypt_and_serialize_fhe_uint16_list(pks, C.uint16_t(value), out)
	case FheUint32:
		C.public_key_encrypt_and_serialize_fhe_uint32_list(pks, C.uint32_t(value), out)
	case FheUint64:
		C.public_key_encrypt_and_serialize_fhe_uint64_list(pks, C.uint64_t(value), out)
	case FheUint160:
		// TODO
		// This function is used to compute ciphertext size, the given value is generally 0,
		value_big := new(big.Int).SetUint64(value)
		input, err := bigIntToU256(value_big)
		if err != nil {
			panic(err)
		}
		C.public_key_encrypt_and_serialize_fhe_uint160_list(pks, input, out)
	}

	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser
}

// bigIntToU256 uses u256_from_big_endian_bytes to convert big.Int to U256
func bigIntToU256(value *big.Int) (*C.U256, error) {
	// Convert big.Int to 32-byte big-endian slice
	bytes := value.Bytes()
	if len(bytes) > 32 {
		return nil, fmt.Errorf("big.Int too large for U256")
	}
	paddedBytes := make([]byte, 32-len(bytes)) // Padding
	paddedBytes = append(paddedBytes, bytes...)

	var result C.U256

	_, err := C.u256_from_big_endian_bytes((*C.uint8_t)(unsafe.Pointer(&paddedBytes[0])), C.size_t(32), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert big.Int to U256: %v", err)
	}

	return &result, nil
}

// u256ToBigInt converts a U256 to a *big.Int.
func u256ToBigInt(u256 C.U256) *big.Int {
	// Allocate a byte slice with enough space (32 bytes for U256)
	buf := make([]byte, 32)

	// Call the C function to fill the buffer with the big-endian bytes of U256
	C.u256_big_endian_bytes(u256, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))

	return new(big.Int).SetBytes(buf)
}
