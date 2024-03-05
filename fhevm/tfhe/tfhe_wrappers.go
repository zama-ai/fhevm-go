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
	}

	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser
}
