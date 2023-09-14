// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package fhevm

import (
	"bytes"
	"math"
	"math/big"
	"testing"
)

// TODO: Don't rely on global keys that are loaded from disk in init(). Instead,
// generate keys on demand in the test.

func TfheEncryptDecrypt(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	}
	ct := new(tfheCiphertext)
	ct.encrypt(val, fheUintType)
	res, err := ct.decrypt()
	if err != nil || res.Uint64() != val.Uint64() {
		t.Fatalf("%d != %d", val.Uint64(), res.Uint64())
	}
}

func TfheTrivialEncryptDecrypt(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	}
	ct := new(tfheCiphertext)
	ct.trivialEncrypt(val, fheUintType)
	res, err := ct.decrypt()
	if err != nil || res.Uint64() != val.Uint64() {
		t.Fatalf("%d != %d", val.Uint64(), res.Uint64())
	}
}

func TfheSerializeDeserialize(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	}
	ct1 := new(tfheCiphertext)
	ct1.encrypt(val, fheUintType)
	ct1Ser := ct1.serialize()
	ct2 := new(tfheCiphertext)
	err := ct2.deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}
}

func TfheSerializeDeserializeCompact(t *testing.T, fheUintType fheUintType) {
	var val uint32
	switch fheUintType {
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	}

	ser := encryptAndSerializeCompact(val, fheUintType)
	ct1 := new(tfheCiphertext)
	err := ct1.deserializeCompact(ser, fheUintType)
	if err != nil {
		t.Fatalf("ct1 compact deserialization failed")
	}
	ct1Ser := ct1.serialize()

	ct2 := new(tfheCiphertext)
	err = ct2.deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("ct2 deserialization failed")
	}

	ct2Ser := ct2.serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}

	decrypted, err := ct2.decrypt()
	if err != nil || uint32(decrypted.Uint64()) != val {
		t.Fatalf("decrypted value is incorrect")
	}
}

func TfheTrivialSerializeDeserialize(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	}
	ct1 := new(tfheCiphertext)
	ct1.trivialEncrypt(val, fheUintType)
	ct1Ser := ct1.serialize()
	ct2 := new(tfheCiphertext)
	err := ct2.deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("trivial serialization is non-deterministic")
	}
}

func TfheDeserializeFailure(t *testing.T, fheUintType fheUintType) {
	ct := new(tfheCiphertext)
	input := make([]byte, 1)
	input[0] = 42
	err := ct.deserialize(input, fheUintType)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TfheDeserializeCompact(t *testing.T, fheUintType fheUintType) {
	var val uint32
	switch fheUintType {
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	}
	ser := encryptAndSerializeCompact(val, fheUintType)
	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(ser, fheUintType)
	if err != nil {
		t.Fatalf("compact deserialization failed")
	}
	decryptedVal, err := ct.decrypt()
	if err != nil || uint32(decryptedVal.Uint64()) != val {
		t.Fatalf("compact deserialization wrong decryption")
	}
}

func TfheDeserializeCompactFailure(t *testing.T, fheUintType fheUintType) {
	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(make([]byte, 10), fheUintType)
	if err == nil {
		t.Fatalf("compact deserialization must have failed")
	}
}

func TfheAdd(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.add(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarAdd(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarAdd(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheSub(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.sub(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarSub(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarSub(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheMul(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.mul(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarMul(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarMul(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarDiv(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(4)
		b.SetUint64(2)
	case FheUint16:
		a.SetUint64(49)
		b.SetUint64(144)
	case FheUint32:
		a.SetUint64(70)
		b.SetInt64(17)
	}
	expected := new(big.Int).Div(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarDiv(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheBitAnd(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := a.Uint64() & b.Uint64()
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.bitand(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheBitOr(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := a.Uint64() | b.Uint64()
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.bitor(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheBitXor(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := a.Uint64() ^ b.Uint64()
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.bitxor(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheShl(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.shl(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarShl(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarShl(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheShr(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.shr(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarShr(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarShr(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheEq(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(2)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(137)
	}
	var expected uint64
	expectedBool := a.Uint64() == b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.eq(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheScalarEq(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	var expected uint64
	expectedBool := a.Uint64() == b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarEq(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheNe(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(2)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(137)
	}
	var expected uint64
	expectedBool := a.Uint64() != b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.ne(ctB)
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheScalarNe(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	var expected uint64
	expectedBool := a.Uint64() != b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes, _ := ctA.scalarNe(b.Uint64())
	res, err := ctRes.decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheGe(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.ge(ctB)
	ctRes2, _ := ctB.ge(ctA)
	res1, err1 := ctRes1.decrypt()
	res2, err2 := ctRes2.decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 1, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarGe(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes1, _ := ctA.scalarGe(b.Uint64())
	res1, err := ctRes1.decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheGt(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.gt(ctB)
	ctRes2, _ := ctB.gt(ctA)
	res1, err1 := ctRes1.decrypt()
	res2, err2 := ctRes2.decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarGt(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes1, _ := ctA.scalarGt(b.Uint64())
	res1, err := ctRes1.decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheLe(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.le(ctB)
	ctRes2, _ := ctB.le(ctA)
	res1, err1 := ctRes1.decrypt()
	res2, err2 := ctRes2.decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarLe(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes1, _ := ctA.scalarLe(b.Uint64())
	res1, err := ctRes1.decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheLt(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.lt(ctB)
	ctRes2, _ := ctB.lt(ctA)
	res1, err1 := ctRes1.decrypt()
	res2, err2 := ctRes2.decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarLt(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes1, _ := ctA.scalarLt(b.Uint64())
	res1, err := ctRes1.decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheMin(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.min(ctB)
	ctRes2, _ := ctB.min(ctA)
	res1, err1 := ctRes1.decrypt()
	res2, err2 := ctRes2.decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TfheScalarMin(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes1, _ := ctA.scalarMin(b.Uint64())
	res1, err1 := ctRes1.decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheMax(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.max(ctB)
	ctRes2, _ := ctB.max(ctA)
	res1, err1 := ctRes1.decrypt()
	res2, err2 := ctRes2.decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TfheScalarMax(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes1, _ := ctA.scalarMax(b.Uint64())
	res1, err1 := ctRes1.decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheNeg(t *testing.T, fheUintType fheUintType) {
	var a big.Int
	var expected uint64

	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		expected = uint64(-uint8(a.Uint64()))
	case FheUint16:
		a.SetUint64(4283)
		expected = uint64(-uint16(a.Uint64()))
	case FheUint32:
		a.SetUint64(1333337)
		expected = uint64(-uint32(a.Uint64()))
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctRes1, _ := ctA.neg()
	res1, err1 := ctRes1.decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TfheNot(t *testing.T, fheUintType fheUintType) {
	var a big.Int
	var expected uint64
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		expected = uint64(^uint8(a.Uint64()))
	case FheUint16:
		a.SetUint64(4283)
		expected = uint64(^uint16(a.Uint64()))
	case FheUint32:
		a.SetUint64(1333337)
		expected = uint64(^uint32(a.Uint64()))
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)

	ctRes1, _ := ctA.not()
	res1, err1 := ctRes1.decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TfheCast(t *testing.T, fheUintTypeFrom fheUintType, fheUintTypeTo fheUintType) {
	var a big.Int
	switch fheUintTypeFrom {
	case FheUint8:
		a.SetUint64(2)
	case FheUint16:
		a.SetUint64(4283)
	case FheUint32:
		a.SetUint64(1333337)
	}

	var modulus uint64
	switch fheUintTypeTo {
	case FheUint8:
		modulus = uint64(math.Pow(2, 8))
	case FheUint16:
		modulus = uint64(math.Pow(2, 16))
	case FheUint32:
		modulus = uint64(math.Pow(2, 32))
	}

	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintTypeFrom)
	ctRes, err := ctA.castTo(fheUintTypeTo)
	if err != nil {
		t.Fatal(err)
	}

	if ctRes.fheUintType != fheUintTypeTo {
		t.Fatalf("type %d != type %d", ctA.fheUintType, fheUintTypeTo)
	}
	res, err := ctRes.decrypt()
	expected := a.Uint64() % modulus
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", res.Uint64(), expected)
	}
}

func TestTfheEncryptDecrypt8(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint8)
}

func TestTfheEncryptDecrypt16(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint16)
}

func TestTfheEncryptDecrypt32(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint32)
}

func TestTfheTrivialEncryptDecrypt8(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint8)
}

func TestTfheTrivialEncryptDecrypt16(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint16)
}

func TestTfheTrivialEncryptDecrypt32(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint32)
}

func TestTfheSerializeDeserialize8(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint8)
}

func TestTfheSerializeDeserialize16(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint16)
}

func TestTfheSerializeDeserialize32(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint32)
}

func TestTfheSerializeDeserializeCompact8(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint8)
}

func TestTfheSerializeDeserializeCompact16(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint16)
}

func TestTfheSerializeDeserializeCompact32(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint32)
}

func TestTfheTrivialSerializeDeserialize8(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint8)
}

func TestTfheTrivialSerializeDeserialize16(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint16)
}

func TestTfheTrivialSerializeDeserialize32(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint32)
}

func TestTfheDeserializeFailure8(t *testing.T) {
	TfheDeserializeFailure(t, FheUint8)
}

func TestTfheDeserializeFailure16(t *testing.T) {
	TfheDeserializeFailure(t, FheUint16)
}

func TestTfheDeserializeFailure32(t *testing.T) {
	TfheDeserializeFailure(t, FheUint32)
}

func TestTfheDeserializeCompact8(t *testing.T) {
	TfheDeserializeCompact(t, FheUint8)
}

func TestTfheDeserializeCompact16(t *testing.T) {
	TfheDeserializeCompact(t, FheUint16)
}

func TestTfheDeserializeCompatc32(t *testing.T) {
	TfheDeserializeCompact(t, FheUint32)
}

func TestTfheDeserializeCompactFailure8(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint8)
}

func TestTfheDeserializeCompactFailure16(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint16)
}

func TestTfheDeserializeCompatcFailure32(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint32)
}

func TestTfheAdd8(t *testing.T) {
	TfheAdd(t, FheUint8)
}

func TestTfheAdd16(t *testing.T) {
	TfheAdd(t, FheUint16)
}

func TestTfheAdd32(t *testing.T) {
	TfheAdd(t, FheUint32)
}

func TestTfheScalarAdd8(t *testing.T) {
	TfheScalarAdd(t, FheUint8)
}

func TestTfheScalarAdd16(t *testing.T) {
	TfheScalarAdd(t, FheUint16)
}

func TestTfheScalarAdd32(t *testing.T) {
	TfheScalarAdd(t, FheUint32)
}

func TestTfheSub8(t *testing.T) {
	TfheSub(t, FheUint8)
}

func TestTfheSub16(t *testing.T) {
	TfheSub(t, FheUint16)
}

func TestTfheSub32(t *testing.T) {
	TfheSub(t, FheUint32)
}

func TestTfheScalarSub8(t *testing.T) {
	TfheScalarSub(t, FheUint8)
}

func TestTfheScalarSub16(t *testing.T) {
	TfheScalarSub(t, FheUint16)
}

func TestTfheScalarSub32(t *testing.T) {
	TfheScalarSub(t, FheUint32)
}

func TestTfheMul8(t *testing.T) {
	TfheMul(t, FheUint8)
}

func TestTfheMul16(t *testing.T) {
	TfheMul(t, FheUint16)
}

func TestTfheMul32(t *testing.T) {
	TfheMul(t, FheUint32)
}

func TestTfheScalarMul8(t *testing.T) {
	TfheScalarMul(t, FheUint8)
}

func TestTfheScalarMul16(t *testing.T) {
	TfheScalarMul(t, FheUint16)
}

func TestTfheScalarMul32(t *testing.T) {
	TfheScalarMul(t, FheUint32)
}

func TestTfheScalarDiv8(t *testing.T) {
	TfheScalarDiv(t, FheUint8)
}

func TestTfheScalarDiv16(t *testing.T) {
	TfheScalarDiv(t, FheUint16)
}

func TestTfheScalarDiv32(t *testing.T) {
	TfheScalarDiv(t, FheUint32)
}

func TestTfheBitAnd8(t *testing.T) {
	TfheBitAnd(t, FheUint8)
}

func TestTfheBitAnd16(t *testing.T) {
	TfheBitAnd(t, FheUint16)
}

func TestTfheBitAnd32(t *testing.T) {
	TfheBitAnd(t, FheUint32)
}

func TestTfheBitOr8(t *testing.T) {
	TfheBitOr(t, FheUint8)
}

func TestTfheBitOr16(t *testing.T) {
	TfheBitOr(t, FheUint16)
}

func TestTfheBitOr32(t *testing.T) {
	TfheBitOr(t, FheUint32)
}

func TestTfheBitXor8(t *testing.T) {
	TfheBitXor(t, FheUint8)
}

func TestTfheBitXor16(t *testing.T) {
	TfheBitXor(t, FheUint16)
}

func TestTfheBitXor32(t *testing.T) {
	TfheBitXor(t, FheUint32)
}

func TestTfheShl8(t *testing.T) {
	TfheShl(t, FheUint8)
}

func TestTfheShl16(t *testing.T) {
	TfheShl(t, FheUint16)
}

func TestTfheShl32(t *testing.T) {
	TfheShl(t, FheUint32)
}

func TestTfheScalarShl8(t *testing.T) {
	TfheScalarShl(t, FheUint8)
}

func TestTfheScalarShl16(t *testing.T) {
	TfheScalarShl(t, FheUint16)
}

func TestTfheScalarShl32(t *testing.T) {
	TfheScalarShl(t, FheUint32)
}

func TestTfheShr8(t *testing.T) {
	TfheShr(t, FheUint8)
}

func TestTfheShr16(t *testing.T) {
	TfheShr(t, FheUint16)
}

func TestTfheShr32(t *testing.T) {
	TfheShr(t, FheUint32)
}

func TestTfheScalarShr8(t *testing.T) {
	TfheScalarShr(t, FheUint8)
}

func TestTfheScalarShr16(t *testing.T) {
	TfheScalarShr(t, FheUint16)
}

func TestTfheScalarShr32(t *testing.T) {
	TfheScalarShr(t, FheUint32)
}

func TestTfheEq8(t *testing.T) {
	TfheEq(t, FheUint8)
}

func TestTfheEq16(t *testing.T) {
	TfheEq(t, FheUint16)
}

func TestTfheEq32(t *testing.T) {
	TfheEq(t, FheUint32)
}

func TestTfheScalarEq8(t *testing.T) {
	TfheScalarEq(t, FheUint8)
}

func TestTfheScalarEq16(t *testing.T) {
	TfheScalarEq(t, FheUint16)
}

func TestTfheScalarEq32(t *testing.T) {
	TfheScalarEq(t, FheUint32)
}

func TestTfheNe8(t *testing.T) {
	TfheNe(t, FheUint8)
}

func TestTfheNe16(t *testing.T) {
	TfheNe(t, FheUint16)
}

func TestTfheNe32(t *testing.T) {
	TfheNe(t, FheUint32)
}

func TestTfheScalarNe8(t *testing.T) {
	TfheScalarNe(t, FheUint8)
}

func TestTfheScalarNe16(t *testing.T) {
	TfheScalarNe(t, FheUint16)
}

func TestTfheScalarNe32(t *testing.T) {
	TfheScalarNe(t, FheUint32)
}

func TestTfheGe8(t *testing.T) {
	TfheGe(t, FheUint8)
}

func TestTfheGe16(t *testing.T) {
	TfheGe(t, FheUint16)
}

func TestTfheGe32(t *testing.T) {
	TfheGe(t, FheUint32)
}

func TestTfheScalarGe8(t *testing.T) {
	TfheScalarGe(t, FheUint8)
}

func TestTfheScalarGe16(t *testing.T) {
	TfheScalarGe(t, FheUint16)
}

func TestTfheScalarGe32(t *testing.T) {
	TfheScalarGe(t, FheUint32)
}

func TestTfheGt8(t *testing.T) {
	TfheGt(t, FheUint8)
}

func TestTfheGt16(t *testing.T) {
	TfheGt(t, FheUint16)
}

func TestTfheGt32(t *testing.T) {
	TfheGt(t, FheUint32)
}

func TestTfheScalarGt8(t *testing.T) {
	TfheScalarGt(t, FheUint8)
}

func TestTfheScalarGt16(t *testing.T) {
	TfheScalarGt(t, FheUint16)
}

func TestTfheScalarGt32(t *testing.T) {
	TfheScalarGt(t, FheUint32)
}

func TestTfheLe8(t *testing.T) {
	TfheLe(t, FheUint8)
}

func TestTfheLe16(t *testing.T) {
	TfheLe(t, FheUint16)
}

func TestTfheLe32(t *testing.T) {
	TfheLe(t, FheUint32)
}

func TestTfheScalarLe8(t *testing.T) {
	TfheScalarLe(t, FheUint8)
}

func TestTfheScalarLe16(t *testing.T) {
	TfheScalarLe(t, FheUint16)
}

func TestTfheScalarLe32(t *testing.T) {
	TfheScalarLe(t, FheUint32)
}

func TestTfheLt8(t *testing.T) {
	TfheLt(t, FheUint8)
}

func TestTfheLt16(t *testing.T) {
	TfheLt(t, FheUint16)
}
func TestTfheLt32(t *testing.T) {
	TfheLt(t, FheUint32)
}

func TestTfheScalarLt8(t *testing.T) {
	TfheScalarLt(t, FheUint8)
}

func TestTfheScalarLt16(t *testing.T) {
	TfheScalarLt(t, FheUint16)
}

func TestTfheScalarLt32(t *testing.T) {
	TfheScalarLt(t, FheUint32)
}

func TestTfheMin8(t *testing.T) {
	TfheMin(t, FheUint8)
}

func TestTfheMin16(t *testing.T) {
	TfheMin(t, FheUint16)
}
func TestTfheMin32(t *testing.T) {
	TfheMin(t, FheUint32)
}

func TestTfheScalarMin8(t *testing.T) {
	TfheScalarMin(t, FheUint8)
}

func TestTfheScalarMin16(t *testing.T) {
	TfheScalarMin(t, FheUint16)
}

func TestTfheScalarMin32(t *testing.T) {
	TfheScalarMin(t, FheUint32)
}

func TestTfheMax8(t *testing.T) {
	TfheMax(t, FheUint8)
}

func TestTfheMax16(t *testing.T) {
	TfheMax(t, FheUint16)
}
func TestTfheMax32(t *testing.T) {
	TfheMax(t, FheUint32)
}

func TestTfheScalarMax8(t *testing.T) {
	TfheScalarMax(t, FheUint8)
}

func TestTfheScalarMax16(t *testing.T) {
	TfheScalarMax(t, FheUint16)
}

func TestTfheScalarMax32(t *testing.T) {
	TfheScalarMax(t, FheUint32)
}

func TestTfheNeg8(t *testing.T) {
	TfheNeg(t, FheUint8)
}

func TestTfheNeg16(t *testing.T) {
	TfheNeg(t, FheUint16)
}
func TestTfheNeg32(t *testing.T) {
	TfheNeg(t, FheUint32)
}

func TestTfheNot8(t *testing.T) {
	TfheNot(t, FheUint8)
}

func TestTfheNot16(t *testing.T) {
	TfheNot(t, FheUint16)
}
func TestTfheNot32(t *testing.T) {
	TfheNot(t, FheUint32)
}

func TestTfhe8Cast16(t *testing.T) {
	TfheCast(t, FheUint8, FheUint16)
}

func TestTfhe8Cast32(t *testing.T) {
	TfheCast(t, FheUint8, FheUint32)
}

func TestTfhe16Cast8(t *testing.T) {
	TfheCast(t, FheUint16, FheUint8)
}

func TestTfhe16Cast32(t *testing.T) {
	TfheCast(t, FheUint16, FheUint32)
}

func TestTfhe32Cast8(t *testing.T) {
	TfheCast(t, FheUint16, FheUint8)
}

func TestTfhe32Cast16(t *testing.T) {
	TfheCast(t, FheUint16, FheUint8)
}
