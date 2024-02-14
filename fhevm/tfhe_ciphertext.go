package fhevm

/*
#include "tfhe_wrappers.h"
*/
import "C"
import (
	"errors"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Represents a TFHE ciphertext type, i.e. its bit capacity.
type FheUintType uint8

const (
	FheUint8  FheUintType = 0
	FheUint16 FheUintType = 1
	FheUint32 FheUintType = 2
	FheUint64 FheUintType = 3
)

func isValidFheType(t byte) bool {
	if uint8(t) < uint8(FheUint8) || uint8(t) > uint8(FheUint64) {
		return false
	}
	return true
}

// Represents an expanded TFHE ciphertext.
type TfheCiphertext struct {
	serialization []byte
	hash          *common.Hash
	fheUintType   FheUintType
}

func (ct *TfheCiphertext) Type() FheUintType {
	return ct.fheUintType
}

// Deserializes a TFHE ciphertext.
func (ct *TfheCiphertext) Deserialize(in []byte, t FheUintType) error {
	switch t {
	case FheUint8:
		ptr := C.deserialize_fhe_uint8(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("FheUint8 ciphertext deserialization failed")
		}
		C.destroy_fhe_uint8(ptr)
	case FheUint16:
		ptr := C.deserialize_fhe_uint16(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("FheUint16 ciphertext deserialization failed")
		}
		C.destroy_fhe_uint16(ptr)
	case FheUint32:
		ptr := C.deserialize_fhe_uint32(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("FheUint32 ciphertext deserialization failed")
		}
		C.destroy_fhe_uint32(ptr)
	case FheUint64:
		ptr := C.deserialize_fhe_uint64(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("FheUint64 ciphertext deserialization failed")
		}
		C.destroy_fhe_uint64(ptr)
	default:
		panic("deserialize: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.serialization = in
	ct.computeHash()
	return nil
}

// Deserializes a compact TFHE ciphetext.
// Note: After the compact TFHE ciphertext has been serialized, subsequent calls to serialize()
// will produce non-compact ciphertext serialziations.
func (ct *TfheCiphertext) DeserializeCompact(in []byte, t FheUintType) error {
	switch t {
	case FheUint8:
		ptr := C.deserialize_compact_fhe_uint8(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint8 ciphertext deserialization failed")
		}
		var err error
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			return err
		}
	case FheUint16:
		ptr := C.deserialize_compact_fhe_uint16(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint16 ciphertext deserialization failed")
		}
		var err error
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			return err
		}
	case FheUint32:
		ptr := C.deserialize_compact_fhe_uint32(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint32 ciphertext deserialization failed")
		}
		var err error
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			return err
		}
	case FheUint64:
		ptr := C.deserialize_compact_fhe_uint64(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint64 ciphertext deserialization failed")
		}
		var err error
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint64(ptr)
		if err != nil {
			return err
		}
	default:
		panic("deserializeCompact: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.computeHash()
	return nil
}

// Encrypts a value as a TFHE ciphertext, using the compact public FHE key.
// The resulting ciphertext is automaticaly expanded.
func (ct *TfheCiphertext) Encrypt(value big.Int, t FheUintType) *TfheCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case FheUint8:
		ptr = C.public_key_encrypt_fhe_uint8(pks, C.uint8_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint16:
		ptr = C.public_key_encrypt_fhe_uint16(pks, C.uint16_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint32:
		ptr = C.public_key_encrypt_fhe_uint32(pks, C.uint32_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint64:
		ptr = C.public_key_encrypt_fhe_uint64(pks, C.uint64_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint64(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("encrypt: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.computeHash()
	return ct
}

func (ct *TfheCiphertext) TrivialEncrypt(value big.Int, t FheUintType) *TfheCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case FheUint8:
		ptr = C.trivial_encrypt_fhe_uint8(sks, C.uint8_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint16:
		ptr = C.trivial_encrypt_fhe_uint16(sks, C.uint16_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint32:
		ptr = C.trivial_encrypt_fhe_uint32(sks, C.uint32_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint64:
		ptr = C.trivial_encrypt_fhe_uint64(sks, C.uint64_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint64(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("trivialEncrypt: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.computeHash()
	return ct
}

func (ct *TfheCiphertext) Serialize() []byte {
	return ct.serialization
}

func (ct *TfheCiphertext) executeUnaryCiphertextOperation(rhs *TfheCiphertext,
	op8 func(ct unsafe.Pointer) unsafe.Pointer,
	op16 func(ct unsafe.Pointer) unsafe.Pointer,
	op32 func(ct unsafe.Pointer) unsafe.Pointer,
	op64 func(ct unsafe.Pointer) unsafe.Pointer) (*TfheCiphertext, error) {

	res := new(TfheCiphertext)
	res.fheUintType = ct.fheUintType
	res_ser := &C.DynamicBuffer{}
	switch ct.fheUintType {
	case FheUint8:
		ct_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((ct.serialization)))
		if ct_ptr == nil {
			return nil, errors.New("8 bit unary op deserialization failed")
		}
		res_ptr := op8(ct_ptr)
		C.destroy_fhe_uint8(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit unary op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		C.destroy_fhe_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit unary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		ct_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((ct.serialization)))
		if ct_ptr == nil {
			return nil, errors.New("16 bit unary op deserialization failed")
		}
		res_ptr := op16(ct_ptr)
		C.destroy_fhe_uint16(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		C.destroy_fhe_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit unary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		ct_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((ct.serialization)))
		if ct_ptr == nil {
			return nil, errors.New("32 bit unary op deserialization failed")
		}
		res_ptr := op32(ct_ptr)
		C.destroy_fhe_uint32(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		C.destroy_fhe_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit unary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		ct_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((ct.serialization)))
		if ct_ptr == nil {
			return nil, errors.New("64 bit unary op deserialization failed")
		}
		res_ptr := op64(ct_ptr)
		C.destroy_fhe_uint64(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit op failed")
		}
		ret := C.serialize_fhe_uint64(res_ptr, res_ser)
		C.destroy_fhe_uint64(res_ptr)
		if ret != 0 {
			return nil, errors.New("64 bit unary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("unary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *TfheCiphertext) executeBinaryCiphertextOperation(rhs *TfheCiphertext,
	op8 func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op16 func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op32 func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op64 func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer) (*TfheCiphertext, error) {
	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(TfheCiphertext)
	res.fheUintType = lhs.fheUintType
	res_ser := &C.DynamicBuffer{}
	switch lhs.fheUintType {
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint8(lhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		res_ptr := op8(lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint8(lhs_ptr)
		C.destroy_fhe_uint8(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit binary op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		C.destroy_fhe_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint16(lhs_ptr)
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		res_ptr := op16(lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint16(lhs_ptr)
		C.destroy_fhe_uint16(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit binary op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		C.destroy_fhe_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint32(lhs_ptr)
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		res_ptr := op32(lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint32(lhs_ptr)
		C.destroy_fhe_uint32(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit binary op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		C.destroy_fhe_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		lhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint64(lhs_ptr)
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		res_ptr := op64(lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint64(lhs_ptr)
		C.destroy_fhe_uint64(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit binary op failed")
		}
		ret := C.serialize_fhe_uint64(res_ptr, res_ser)
		C.destroy_fhe_uint64(res_ptr)
		if ret != 0 {
			return nil, errors.New("64 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("binary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (first *TfheCiphertext) executeTernaryCiphertextOperation(lhs *TfheCiphertext, rhs *TfheCiphertext,
	op8 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op16 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op32 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op64 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer) (*TfheCiphertext, error) {
	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("ternary operations are only well-defined for identical types")
	}

	res := new(TfheCiphertext)
	res.fheUintType = lhs.fheUintType
	res_ser := &C.DynamicBuffer{}
	switch lhs.fheUintType {
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint8(lhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((first.serialization)))
		if first_ptr == nil {
			C.destroy_fhe_uint8(lhs_ptr)
			C.destroy_fhe_uint8(rhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		res_ptr := op8(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint8(lhs_ptr)
		C.destroy_fhe_uint8(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit binary op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		C.destroy_fhe_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint16(lhs_ptr)
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((first.serialization)))
		if first_ptr == nil {
			C.destroy_fhe_uint8(lhs_ptr)
			C.destroy_fhe_uint8(rhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		res_ptr := op16(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint16(lhs_ptr)
		C.destroy_fhe_uint16(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit binary op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		C.destroy_fhe_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint32(lhs_ptr)
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((first.serialization)))
		if first_ptr == nil {
			C.destroy_fhe_uint8(lhs_ptr)
			C.destroy_fhe_uint8(rhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		res_ptr := op32(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint32(lhs_ptr)
		C.destroy_fhe_uint32(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit binary op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		C.destroy_fhe_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		lhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint64(lhs_ptr)
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((first.serialization)))
		if first_ptr == nil {
			C.destroy_fhe_uint8(lhs_ptr)
			C.destroy_fhe_uint8(rhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		res_ptr := op64(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint64(lhs_ptr)
		C.destroy_fhe_uint64(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit binary op failed")
		}
		ret := C.serialize_fhe_uint64(res_ptr, res_ser)
		C.destroy_fhe_uint64(res_ptr)
		if ret != 0 {
			return nil, errors.New("64 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("binary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *TfheCiphertext) executeBinaryScalarOperation(rhs uint64,
	op8 func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer,
	op16 func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer,
	op32 func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer,
	op64 func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer) (*TfheCiphertext, error) {
	res := new(TfheCiphertext)
	res.fheUintType = lhs.fheUintType
	res_ser := &C.DynamicBuffer{}
	switch lhs.fheUintType {
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit scalar op deserialization failed")
		}
		scalar := C.uint8_t(rhs)
		res_ptr := op8(lhs_ptr, scalar)
		C.destroy_fhe_uint8(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit scalar op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		C.destroy_fhe_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit scalar op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit scalar op deserialization failed")
		}
		scalar := C.uint16_t(rhs)
		res_ptr := op16(lhs_ptr, scalar)
		C.destroy_fhe_uint16(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit scalar op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		C.destroy_fhe_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit scalar op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit scalar op deserialization failed")
		}
		scalar := C.uint32_t(rhs)
		res_ptr := op32(lhs_ptr, scalar)
		C.destroy_fhe_uint32(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit scalar op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		C.destroy_fhe_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit scalar op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		lhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit scalar op deserialization failed")
		}
		scalar := C.uint64_t(rhs)
		res_ptr := op64(lhs_ptr, scalar)
		C.destroy_fhe_uint64(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit scalar op failed")
		}
		ret := C.serialize_fhe_uint64(res_ptr, res_ser)
		C.destroy_fhe_uint64(res_ptr)
		if ret != 0 {
			return nil, errors.New("64 bit scalar op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("scalar op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *TfheCiphertext) Add(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.add_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.add_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.add_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.add_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarAdd(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_add_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_add_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_add_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_add_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Sub(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.sub_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.sub_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.sub_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.sub_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarSub(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_sub_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_sub_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_sub_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_sub_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Mul(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.mul_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.mul_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.mul_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.mul_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarMul(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_mul_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_mul_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_mul_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_mul_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarDiv(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_div_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_div_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_div_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_div_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarRem(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_rem_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_rem_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_rem_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_rem_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Bitand(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitand_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitand_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitand_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitand_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Bitor(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitor_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitor_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitor_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitor_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Bitxor(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitxor_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitxor_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitxor_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitxor_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Shl(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shl_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shl_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shl_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shl_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarShl(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_shl_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_shl_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_shl_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_shl_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Shr(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shr_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shr_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shr_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shr_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarShr(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_shr_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_shr_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_shr_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_shr_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Eq(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.eq_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.eq_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.eq_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.eq_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarEq(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_eq_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_eq_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_eq_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_eq_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Ne(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ne_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ne_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ne_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ne_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarNe(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_ne_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_ne_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_ne_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_ne_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Ge(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ge_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ge_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ge_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ge_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarGe(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_ge_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_ge_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_ge_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_ge_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Gt(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.gt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.gt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.gt_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.gt_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarGt(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_gt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_gt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_gt_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_gt_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Le(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.le_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.le_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.le_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.le_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarLe(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_le_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_le_fhe_uint16(lhs, rhs, sks)

		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_le_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_le_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Lt(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.lt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.lt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.lt_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.lt_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarLt(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_lt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_lt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_lt_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_lt_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Min(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.min_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.min_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.min_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.min_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarMin(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_min_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_min_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_min_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_min_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Max(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.max_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.max_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.max_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.max_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) ScalarMax(rhs uint64) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_max_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_max_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_max_fhe_uint32(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) unsafe.Pointer {
			return C.scalar_max_fhe_uint64(lhs, rhs, sks)
		})
}

func (lhs *TfheCiphertext) Neg() (*TfheCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.neg_fhe_uint8(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.neg_fhe_uint16(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.neg_fhe_uint32(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.neg_fhe_uint64(lhs, sks)
		})
}

func (lhs *TfheCiphertext) Not() (*TfheCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.not_fhe_uint8(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.not_fhe_uint16(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.not_fhe_uint32(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.not_fhe_uint64(lhs, sks)
		})
}

func (condition *TfheCiphertext) IfThenElse(lhs *TfheCiphertext, rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return condition.executeTernaryCiphertextOperation(lhs, rhs,
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint8(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint16(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint32(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint64(condition, lhs, rhs, sks)
		})
}

func (ct *TfheCiphertext) CastTo(castToType FheUintType) (*TfheCiphertext, error) {
	if ct.fheUintType == castToType {
		return nil, errors.New("casting to same type is not supported")
	}

	res := new(TfheCiphertext)
	res.fheUintType = castToType

	switch ct.fheUintType {
	case FheUint8:
		switch castToType {
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_16(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint16")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_32(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint32")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_64(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint64")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case FheUint16:
		switch castToType {
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_8(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint8")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_32(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint32")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_64(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint64")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case FheUint32:
		switch castToType {
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_8(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint8")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_16(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint16")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_64(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint64")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case FheUint64:
		switch castToType {
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint64 ciphertext")
			}
			to_ptr := C.cast_64_8(from_ptr, sks)
			C.destroy_fhe_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint64 to FheUint8")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint64 ciphertext")
			}
			to_ptr := C.cast_64_16(from_ptr, sks)
			C.destroy_fhe_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint64 to FheUint16")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint64 ciphertext")
			}
			to_ptr := C.cast_64_32(from_ptr, sks)
			C.destroy_fhe_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint64 to FheUint32")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	}
	res.computeHash()
	return res, nil
}

func (ct *TfheCiphertext) Decrypt() (big.Int, error) {
	if cks == nil {
		return *new(big.Int).SetUint64(0), errors.New("cks is not initialized")
	}
	var value uint64
	var ret C.int
	switch ct.fheUintType {
	case FheUint8:
		ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint8")
		}
		var result C.uint8_t
		ret = C.decrypt_fhe_uint8(cks, ptr, &result)
		C.destroy_fhe_uint8(ptr)
		value = uint64(result)
	case FheUint16:
		ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint16")
		}
		var result C.uint16_t
		ret = C.decrypt_fhe_uint16(cks, ptr, &result)
		C.destroy_fhe_uint16(ptr)
		value = uint64(result)
	case FheUint32:
		ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint32")
		}
		var result C.uint32_t
		ret = C.decrypt_fhe_uint32(cks, ptr, &result)
		C.destroy_fhe_uint32(ptr)
		value = uint64(result)
	case FheUint64:
		ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint64")
		}
		var result C.uint64_t
		ret = C.decrypt_fhe_uint64(cks, ptr, &result)
		C.destroy_fhe_uint64(ptr)
		value = uint64(result)
	default:
		panic("decrypt: unexpected ciphertext type")
	}
	if ret != 0 {
		return *new(big.Int).SetUint64(0), errors.New("decrypt failed")
	}
	return *new(big.Int).SetUint64(value), nil
}

func (ct *TfheCiphertext) computeHash() {
	hash := common.BytesToHash(crypto.Keccak256(ct.serialization))
	ct.hash = &hash
}

func (ct *TfheCiphertext) GetHash() common.Hash {
	if ct.hash != nil {
		return *ct.hash
	}
	ct.computeHash()
	return *ct.hash
}
