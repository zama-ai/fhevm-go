package fhevm

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"os"
	"testing"
)

// generate keys if not present
func setup() {
	if !allGlobalKeysPresent() {
		fmt.Println("INFO: initializing global keys in tests")
		initGlobalKeysWithNewKeys()
	}
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}

func TfheEncryptDecrypt(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	case FheUint64:
		val.SetUint64(13333377777777777)
	}
	ct := new(TfheCiphertext)
	ct.Encrypt(val, fheUintType)
	res, err := ct.Decrypt()
	if err != nil || res.Uint64() != val.Uint64() {
		t.Fatalf("%d != %d", val.Uint64(), res.Uint64())
	}
}

func TfheTrivialEncryptDecrypt(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	case FheUint64:
		val.SetUint64(13333377777777777)
	}
	ct := new(TfheCiphertext)
	ct.TrivialEncrypt(val, fheUintType)
	res, err := ct.Decrypt()
	if err != nil || res.Uint64() != val.Uint64() {
		t.Fatalf("%d != %d", val.Uint64(), res.Uint64())
	}
}

func TfheSerializeDeserialize(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	case FheUint64:
		val = *big.NewInt(13333377777777777)
	}
	ct1 := new(TfheCiphertext)
	ct1.Encrypt(val, fheUintType)
	ct1Ser := ct1.Serialize()
	ct2 := new(TfheCiphertext)
	err := ct2.Deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}
}

func TfheSerializeDeserializeCompact(t *testing.T, fheUintType FheUintType) {
	var val uint64
	switch fheUintType {
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	case FheUint64:
		val = 13333377777777777
	}

	ser := encryptAndSerializeCompact(val, fheUintType)
	ct1 := new(TfheCiphertext)
	err := ct1.DeserializeCompact(ser, fheUintType)
	if err != nil {
		t.Fatalf("ct1 compact deserialization failed")
	}
	ct1Ser := ct1.Serialize()

	ct2 := new(TfheCiphertext)
	err = ct2.Deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("ct2 deserialization failed")
	}

	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}

	decrypted, err := ct2.Decrypt()
	if err != nil || uint64(decrypted.Uint64()) != val {
		t.Fatalf("decrypted value is incorrect")
	}
}

func TfheTrivialSerializeDeserialize(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	case FheUint64:
		val = *big.NewInt(13333377777777777)
	}
	ct1 := new(TfheCiphertext)
	ct1.TrivialEncrypt(val, fheUintType)
	ct1Ser := ct1.Serialize()
	ct2 := new(TfheCiphertext)
	err := ct2.Deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("trivial serialization is non-deterministic")
	}
}

func TfheDeserializeFailure(t *testing.T, fheUintType FheUintType) {
	ct := new(TfheCiphertext)
	input := make([]byte, 1)
	input[0] = 42
	err := ct.Deserialize(input, fheUintType)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TfheDeserializeCompact(t *testing.T, fheUintType FheUintType) {
	var val uint64
	switch fheUintType {
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	case FheUint64:
		val = 13333377777777777
	}
	ser := encryptAndSerializeCompact(val, fheUintType)
	ct := new(TfheCiphertext)
	err := ct.DeserializeCompact(ser, fheUintType)
	if err != nil {
		t.Fatalf("compact deserialization failed")
	}
	decryptedVal, err := ct.Decrypt()
	if err != nil || uint64(decryptedVal.Uint64()) != val {
		t.Fatalf("compact deserialization wrong decryption")
	}
}

func TfheDeserializeCompactFailure(t *testing.T, fheUintType FheUintType) {
	ct := new(TfheCiphertext)
	err := ct.DeserializeCompact(make([]byte, 10), fheUintType)
	if err == nil {
		t.Fatalf("compact deserialization must have failed")
	}
}

func TfheAdd(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Add(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarAdd(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarAdd(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheSub(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Sub(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarSub(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarSub(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheMul(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(133)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Mul(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarMul(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(133)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarMul(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarDiv(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Div(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarDiv(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarRem(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rem(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarRem(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheBitAnd(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() & b.Uint64()
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Bitand(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheBitOr(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() | b.Uint64()
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Bitor(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheBitXor(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() ^ b.Uint64()
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Bitxor(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheShl(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Shl(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarShl(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarShl(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheShr(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Shr(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarShr(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarShr(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheEq(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(1337)
	}
	var expected uint64
	expectedBool := a.Uint64() == b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Eq(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheScalarEq(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	var expected uint64
	expectedBool := a.Uint64() == b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarEq(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheNe(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(1337)
	}
	var expected uint64
	expectedBool := a.Uint64() != b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Ne(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheScalarNe(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	var expected uint64
	expectedBool := a.Uint64() != b.Uint64()
	if expectedBool {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarNe(b.Uint64())
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheGe(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Ge(ctB)
	ctRes2, _ := ctB.Ge(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 1, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarGe(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarGe(b.Uint64())
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheGt(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Gt(ctB)
	ctRes2, _ := ctB.Gt(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarGt(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarGt(b.Uint64())
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheLe(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Le(ctB)
	ctRes2, _ := ctB.Le(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarLe(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarLe(b.Uint64())
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheLt(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Lt(ctB)
	ctRes2, _ := ctB.Lt(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarLt(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarLt(b.Uint64())
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheMin(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Min(ctB)
	ctRes2, _ := ctB.Min(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TfheScalarMin(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarMin(b.Uint64())
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheMax(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Max(ctB)
	ctRes2, _ := ctB.Max(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TfheScalarMax(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarMax(b.Uint64())
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheNeg(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13333377777777777)
		expected = uint64(-uint64(a.Uint64()))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.Neg()
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TfheNot(t *testing.T, fheUintType FheUintType) {
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
	case FheUint64:
		a.SetUint64(13333377777777777)
		expected = uint64(^uint64(a.Uint64()))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)

	ctRes1, _ := ctA.Not()
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TfheIfThenElse(t *testing.T, fheUintType FheUintType) {
	var condition, condition2, a, b big.Int
	condition.SetUint64(1)
	condition2.SetUint64(0)
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
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337)
	}
	ctCondition := new(TfheCiphertext)
	ctCondition.Encrypt(condition, fheUintType)
	ctCondition2 := new(TfheCiphertext)
	ctCondition2.Encrypt(condition2, fheUintType)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctCondition.IfThenElse(ctA, ctB)
	ctRes2, _ := ctCondition2.IfThenElse(ctA, ctB)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheCast(t *testing.T, fheUintTypeFrom FheUintType, fheUintTypeTo FheUintType) {
	var a big.Int
	switch fheUintTypeFrom {
	case FheUint8:
		a.SetUint64(2)
	case FheUint16:
		a.SetUint64(4283)
	case FheUint32:
		a.SetUint64(1333337)
	case FheUint64:
		a.SetUint64(13333377777777777)
	}

	var modulus uint64
	switch fheUintTypeTo {
	case FheUint8:
		modulus = uint64(math.Pow(2, 8))
	case FheUint16:
		modulus = uint64(math.Pow(2, 16))
	case FheUint32:
		modulus = uint64(math.Pow(2, 32))
	case FheUint64:
		modulus = uint64(math.Pow(2, 64))
	}

	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintTypeFrom)
	ctRes, err := ctA.CastTo(fheUintTypeTo)
	if err != nil {
		t.Fatal(err)
	}

	if ctRes.fheUintType != fheUintTypeTo {
		t.Fatalf("type %d != type %d", ctA.fheUintType, fheUintTypeTo)
	}
	res, err := ctRes.Decrypt()
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

func TestTfheEncryptDecrypt64(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint64)
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

func TestTfheTrivialEncryptDecrypt64(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint64)
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

func TestTfheSerializeDeserialize64(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint64)
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

func TestTfheSerializeDeserializeCompact64(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint64)
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

func TestTfheTrivialSerializeDeserialize64(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint64)
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

func TestTfheDeserializeFailure64(t *testing.T) {
	TfheDeserializeFailure(t, FheUint64)
}

func TestTfheDeserializeCompact8(t *testing.T) {
	TfheDeserializeCompact(t, FheUint8)
}

func TestTfheDeserializeCompact16(t *testing.T) {
	TfheDeserializeCompact(t, FheUint16)
}

func TestTfheDeserializeCompact32(t *testing.T) {
	TfheDeserializeCompact(t, FheUint32)
}

func TestTfheDeserializeCompact64(t *testing.T) {
	TfheDeserializeCompact(t, FheUint64)
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

func TestTfheDeserializeCompatcFailure64(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint64)
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

func TestTfheAdd64(t *testing.T) {
	TfheAdd(t, FheUint64)
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

func TestTfheScalarAdd64(t *testing.T) {
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

func TestTfheSub64(t *testing.T) {
	TfheSub(t, FheUint64)
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

func TestTfheScalarSub64(t *testing.T) {
	TfheScalarSub(t, FheUint64)
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

func TestTfheMul64(t *testing.T) {
	TfheMul(t, FheUint64)
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

func TestTfheScalarMul64(t *testing.T) {
	TfheScalarMul(t, FheUint64)
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

func TestTfheScalarDiv64(t *testing.T) {
	TfheScalarDiv(t, FheUint64)
}

func TestTfheScalarRem8(t *testing.T) {
	TfheScalarRem(t, FheUint8)
}

func TestTfheScalarRem16(t *testing.T) {
	TfheScalarRem(t, FheUint16)
}

func TestTfheScalarRem32(t *testing.T) {
	TfheScalarRem(t, FheUint32)
}

func TestTfheScalarRem64(t *testing.T) {
	TfheScalarRem(t, FheUint64)
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

func TestTfheBitAnd64(t *testing.T) {
	TfheBitAnd(t, FheUint64)
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

func TestTfheBitOr64(t *testing.T) {
	TfheBitOr(t, FheUint64)
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

func TestTfheBitXor64(t *testing.T) {
	TfheBitXor(t, FheUint64)
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

func TestTfheShl64(t *testing.T) {
	TfheShl(t, FheUint64)
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

func TestTfheScalarShl64(t *testing.T) {
	TfheScalarShl(t, FheUint64)
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

func TestTfheShr64(t *testing.T) {
	TfheShr(t, FheUint64)
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

func TestTfheScalarShr64(t *testing.T) {
	TfheScalarShr(t, FheUint64)
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

func TestTfheEq64(t *testing.T) {
	TfheEq(t, FheUint64)
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

func TestTfheScalarEq64(t *testing.T) {
	TfheScalarEq(t, FheUint64)
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

func TestTfheNe64(t *testing.T) {
	TfheNe(t, FheUint64)
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

func TestTfheScalarNe64(t *testing.T) {
	TfheScalarNe(t, FheUint64)
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

func TestTfheGe64(t *testing.T) {
	TfheGe(t, FheUint64)
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

func TestTfheScalarGe64(t *testing.T) {
	TfheScalarGe(t, FheUint64)
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

func TestTfheGt64(t *testing.T) {
	TfheGt(t, FheUint64)
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

func TestTfheScalarGt64(t *testing.T) {
	TfheScalarGt(t, FheUint64)
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

func TestTfheLe64(t *testing.T) {
	TfheLe(t, FheUint64)
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

func TestTfheScalarLe64(t *testing.T) {
	TfheScalarLe(t, FheUint64)
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
func TestTfheLt64(t *testing.T) {
	TfheLt(t, FheUint64)
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

func TestTfheScalarLt64(t *testing.T) {
	TfheScalarLt(t, FheUint64)
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
func TestTfheMin64(t *testing.T) {
	TfheMin(t, FheUint64)
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

func TestTfheScalarMin64(t *testing.T) {
	TfheScalarMin(t, FheUint64)
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
func TestTfheMax64(t *testing.T) {
	TfheMax(t, FheUint64)
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

func TestTfheScalarMax64(t *testing.T) {
	TfheScalarMax(t, FheUint64)
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
func TestTfheNeg64(t *testing.T) {
	TfheNeg(t, FheUint64)
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
func TestTfheNot64(t *testing.T) {
	TfheNot(t, FheUint64)
}

func TestTfheIfThenElse8(t *testing.T) {
	TfheIfThenElse(t, FheUint8)
}

func TestTfheIfThenElse16(t *testing.T) {
	TfheIfThenElse(t, FheUint16)
}
func TestTfheIfThenElse32(t *testing.T) {
	TfheIfThenElse(t, FheUint32)
}
func TestTfheIfThenElse64(t *testing.T) {
	TfheIfThenElse(t, FheUint64)
}

func TestTfhe8Cast16(t *testing.T) {
	TfheCast(t, FheUint8, FheUint16)
}

func TestTfhe8Cast32(t *testing.T) {
	TfheCast(t, FheUint8, FheUint32)
}

func TestTfhe8Cast64(t *testing.T) {
	TfheCast(t, FheUint8, FheUint64)
}

func TestTfhe16Cast8(t *testing.T) {
	TfheCast(t, FheUint16, FheUint8)
}

func TestTfhe16Cast32(t *testing.T) {
	TfheCast(t, FheUint16, FheUint32)
}

func TestTfhe16Cast64(t *testing.T) {
	TfheCast(t, FheUint16, FheUint64)
}

func TestTfhe32Cast8(t *testing.T) {
	TfheCast(t, FheUint32, FheUint8)
}

func TestTfhe32Cast16(t *testing.T) {
	TfheCast(t, FheUint32, FheUint16)
}

func TestTfhe32Cast64(t *testing.T) {
	TfheCast(t, FheUint32, FheUint64)
}

func TestTfhe64Cast8(t *testing.T) {
	TfheCast(t, FheUint64, FheUint8)
}

func TestTfhe64Cast16(t *testing.T) {
	TfheCast(t, FheUint64, FheUint16)
}

func TestTfhe64Cast32(t *testing.T) {
	TfheCast(t, FheUint64, FheUint32)
}
