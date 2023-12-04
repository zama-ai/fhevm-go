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
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
)

func init() {
	// register errors from geth so that tests recognize them
	RegisterErrors(
		vm.ErrOutOfGas,
		vm.ErrCodeStoreOutOfGas,
		vm.ErrDepth,
		vm.ErrInsufficientBalance,
		vm.ErrContractAddressCollision,
		vm.ErrExecutionReverted,
		vm.ErrMaxInitCodeSizeExceeded,
		vm.ErrMaxCodeSizeExceeded,
		vm.ErrInvalidJump,
		vm.ErrWriteProtection,
		vm.ErrReturnDataOutOfBounds,
		vm.ErrGasUintOverflow,
		vm.ErrInvalidCode,
		vm.ErrNonceUintOverflow,
		nil,
		nil,
		nil,
	)
}

func toPrecompileInput(isScalar bool, hashes ...common.Hash) []byte {
	ret := make([]byte, 0)
	for _, hash := range hashes {
		ret = append(ret, hash.Bytes()...)
	}
	var isScalarByte byte
	if isScalar {
		isScalarByte = 1
	} else {
		isScalarByte = 0
	}
	ret = append(ret, isScalarByte)
	return ret
}

var scalarBytePadding = make([]byte, 31)

func toLibPrecompileInput(method string, isScalar bool, hashes ...common.Hash) []byte {
	ret := make([]byte, 0)
	hashRes := crypto.Keccak256([]byte(method))
	signature := hashRes[0:4]
	ret = append(ret, signature...)
	for _, hash := range hashes {
		ret = append(ret, hash.Bytes()...)
	}
	var isScalarByte byte
	if isScalar {
		isScalarByte = 1
	} else {
		isScalarByte = 0
	}
	ret = append(ret, isScalarByte)
	ret = append(ret, scalarBytePadding...)
	return ret
}

func toLibPrecompileInputNoScalar(method string, hashes ...common.Hash) []byte {
	ret := make([]byte, 0)
	hashRes := crypto.Keccak256([]byte(method))
	signature := hashRes[0:4]
	ret = append(ret, signature...)
	for _, hash := range hashes {
		ret = append(ret, hash.Bytes()...)
	}
	return ret
}

func VerifyCiphertext(t *testing.T, fheUintType FheUintType) {
	var value uint32
	switch fheUintType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	compact := encryptAndSerializeCompact(value, fheUintType)
	input := append(compact, byte(fheUintType))
	out, err := verifyCiphertextRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(tfheCiphertext)
	if err = ct.deserializeCompact(compact, fheUintType); err != nil {
		t.Fatalf(err.Error())
	}
	if common.BytesToHash(out) != ct.getHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(environment, ct.getHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func VerifyCiphertextBadType(t *testing.T, actualType FheUintType, metadataType FheUintType) {
	var value uint32
	switch actualType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	compact := encryptAndSerializeCompact(value, actualType)
	input := append(compact, byte(metadataType))
	_, err := verifyCiphertextRun(environment, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on type mismatch")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("verifyCiphertext mustn't have verified given ciphertext")
	}
}

func TrivialEncrypt(t *testing.T, fheUintType FheUintType) {
	var value big.Int
	switch fheUintType {
	case FheUint8:
		value = *big.NewInt(2)
	case FheUint16:
		value = *big.NewInt(4283)
	case FheUint32:
		value = *big.NewInt(1333337)
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	valueBytes := make([]byte, 32)
	input := append(value.FillBytes(valueBytes), byte(fheUintType))
	out, err := trivialEncryptRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(tfheCiphertext).trivialEncrypt(value, fheUintType)
	if common.BytesToHash(out) != ct.getHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(environment, ct.getHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func FheLibAdd(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs + rhs
	signature := "fheAdd(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibSub(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs - rhs
	signature := "fheSub(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibMul(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 3
		rhs = 2
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs * rhs
	signature := "fheMul(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibLe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	signature := "fheLe(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	// lhs <= rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs <= lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = FheLibRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLibLt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	signature := "fheLt(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	// lhs < rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs < lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = FheLibRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLibEq(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	signature := "fheLt(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}
}

func FheLibGe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	signature := "fheGe(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs >= rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs >= lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = FheLibRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLibGt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	signature := "fheGt(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs > rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs > lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = FheLibRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLibShl(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs << rhs
	signature := "fheShl(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibShr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs >> rhs
	signature := "fheShr(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibNe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	signature := "fheNe(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
}

func FheLibMin(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	signature := "fheMin(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != rhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = FheLibRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != rhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
		}
	}
}

func FheLibMax(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	signature := "fheMax(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != lhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = FheLibRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != lhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
		}
	}
}

func FheLibNeg(t *testing.T, fheUintType FheUintType) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(-uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(-uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(-uint32(pt))
	}

	signature := "fheNeg(uint256)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).getHash()

	input := toLibPrecompileInputNoScalar(signature, ptHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibNot(t *testing.T, fheUintType FheUintType) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(^uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(^uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(^uint32(pt))
	}

	signature := "fheNot(uint256)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).getHash()

	input := toLibPrecompileInputNoScalar(signature, ptHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibDiv(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 4
		rhs = 2
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 137
		rhs = 17
	}
	expected := lhs / rhs

	signature := "fheDiv(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar multiplication should fail")
		}
	}
}

func FheLibRem(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 7
		rhs = 3
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 1337
		rhs = 73
	}
	expected := lhs % rhs
	signature := "fheRem(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar remainder should fail")
		}
	}
}

func FheLibBitAnd(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs & rhs
	signature := "fheBitAnd(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit and should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibBitOr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs | rhs
	signature := "fheBitOr(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit or should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibBitXor(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs ^ rhs
	signature := "fheBitXor(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit xor should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibRand(t *testing.T, fheUintType FheUintType) {
	signature := "fheRand(bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, byte(fheUintType))
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("fheRand expected output len of 32, got %v", len(out))
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 1 {
		t.Fatalf("fheRand expected 1 verified ciphertext")
	}

	hash := common.BytesToHash(out)
	_, err = environment.FhevmData().verifiedCiphertexts[hash].ciphertext.decrypt()
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func LibTrivialEncrypt(t *testing.T, fheUintType FheUintType) {
	var value big.Int
	switch fheUintType {
	case FheUint8:
		value = *big.NewInt(2)
	case FheUint16:
		value = *big.NewInt(4283)
	case FheUint32:
		value = *big.NewInt(1333337)
	}
	signature := "trivialEncrypt(uint256,bytes1)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	valueBytes := make([]byte, 32)
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, value.FillBytes(valueBytes)...)
	input = append(input, byte(fheUintType))
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(tfheCiphertext).trivialEncrypt(value, fheUintType)
	if common.BytesToHash(out) != ct.getHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(environment, ct.getHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func LibDecrypt(t *testing.T, fheUintType FheUintType) {
	var value uint64
	switch fheUintType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	signature := "decrypt(uint256)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	hash := verifyCiphertextInTestMemory(environment, value, depth, fheUintType).getHash()
	input = append(input, signatureBytes...)
	input = append(input, hash.Bytes()...)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("decrypt expected output len of 32, got %v", len(out))
	}
	result := big.Int{}
	result.SetBytes(out)
	if result.Uint64() != value {
		t.Fatalf("decrypt result not equal to value, result %v != value %v", result.Uint64(), value)
	}
}

func TestLibVerifyCiphertextInvalidType(t *testing.T) {
	signature := "verifyCiphertext(bytes)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := FheUintType(255)
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	compact := encryptAndSerializeCompact(0, FheUint32)
	input = append(input, compact...)
	input = append(input, byte(invalidType))
	_, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on invalid ciphertext type")
	}

	if !strings.Contains(err.Error(), "ciphertext type is invalid") {
		t.Fatalf("Unexpected test error: %s", err.Error())
	}
}

func TestLibReencrypt(t *testing.T) {
	signature := "reencrypt(uint256,uint256)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	environment.ethCall = true
	toEncrypt := 7
	fheUintType := FheUint8
	encCiphertext := verifyCiphertextInTestMemory(environment, uint64(toEncrypt), depth, fheUintType).getHash()
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, encCiphertext.Bytes()...)
	// just append twice not to generate public key
	input = append(input, encCiphertext.Bytes()...)
	_, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf("Reencrypt error: %s", err.Error())
	}
}

func TestLibCast(t *testing.T) {
	signature := "cast(uint256,bytes1)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	environment.ethCall = true
	toEncrypt := 7
	fheUintType := FheUint8
	encCiphertext := verifyCiphertextInTestMemory(environment, uint64(toEncrypt), depth, fheUintType).getHash()
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, encCiphertext.Bytes()...)
	input = append(input, byte(FheUint32))
	_, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf("Cast error: %s", err.Error())
	}
}

func FheAdd(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs + rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheAddRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheSub(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs - rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheSubRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheMul(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 169
		rhs = 5
	case FheUint32:
		lhs = 137
		rhs = 17
	}
	expected := lhs * rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheMulRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheDiv(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 4
		rhs = 2
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 137
		rhs = 17
	}
	expected := lhs / rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheDivRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar multiplication should fail")
		}
	}
}

func FheRem(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 9
		rhs = 5
	case FheUint16:
		lhs = 1773
		rhs = 523
	case FheUint32:
		lhs = 123765
		rhs = 2179
	}
	expected := lhs % rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheRemRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar remainder should fail")
		}
	}
}

func FheBitAnd(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs & rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheBitAndRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit and should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheBitOr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs | rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheBitOrRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit or should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheBitXor(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs ^ rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheBitXorRun(environment, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit xor should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheShl(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs << rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheShlRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheShr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs >> rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheShrRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheEq(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheEqRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}
}

func FheNe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheNeRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
}

func FheGe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs >= rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheGeRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs >= lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheGeRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheGt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}
	// lhs > rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheGtRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs > lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheGtRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	// lhs <= rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheLeRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs <= lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheLeRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	// lhs < rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheLtRun(environment, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs < lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheLtRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheMin(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheMinRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != rhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheMinRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != rhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
		}
	}
}

func FheMax(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).getHash()
	}

	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheMaxRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != lhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheMaxRun(environment, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != lhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
		}
	}
}

func FheNeg(t *testing.T, fheUintType FheUintType, scalar bool) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(-uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(-uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(-uint32(pt))
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).getHash()

	input := make([]byte, 0)
	input = append(input, ptHash.Bytes()...)
	out, err := fheNegRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheNot(t *testing.T, fheUintType FheUintType, scalar bool) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(^uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(^uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(^uint32(pt))
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).getHash()

	input := make([]byte, 0)
	input = append(input, ptHash.Bytes()...)
	out, err := fheNotRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func Decrypt(t *testing.T, fheUintType FheUintType) {
	var value uint64
	switch fheUintType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(environment, value, depth, fheUintType).getHash()
	out, err := decryptRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("decrypt expected output len of 32, got %v", len(out))
	}
	result := big.Int{}
	result.SetBytes(out)
	if result.Uint64() != value {
		t.Fatalf("decrypt result not equal to value, result %v != value %v", result.Uint64(), value)
	}
}

func FheRand(t *testing.T, fheUintType FheUintType) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	out, err := fheRandRun(environment, addr, addr, []byte{byte(fheUintType)}, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("fheRand expected output len of 32, got %v", len(out))
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 1 {
		t.Fatalf("fheRand expected 1 verified ciphertext")
	}

	hash := common.BytesToHash(out)
	_, err = environment.FhevmData().verifiedCiphertexts[hash].ciphertext.decrypt()
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestVerifyCiphertextInvalidType(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := FheUintType(255)
	compact := encryptAndSerializeCompact(0, FheUint32)
	input := append(compact, byte(invalidType))
	_, err := verifyCiphertextRun(environment, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on invalid ciphertext type")
	}
}

func TestTrivialEncryptInvalidType(t *testing.T) {
	// TODO: maybe trivialEncryptRun shouldn't panic but return an error?
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("trivialEncrypt must have failed (panic) on invalid ciphertext type")
		}
	}()
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := FheUintType(255)
	input := make([]byte, 32)
	input = append(input, byte(invalidType))
	trivialEncryptRun(environment, addr, addr, input, readOnly)
}

func TestCastInvalidType(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := FheUintType(255)
	hash := verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).getHash()
	input := make([]byte, 0)
	input = append(input, hash.Bytes()...)
	input = append(input, byte(invalidType))
	_, err := castRun(environment, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("cast must have failed on invalid ciphertext type")
	}
}

func TestVerifyCiphertextInvalidSize(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ctType := FheUint32
	compact := encryptAndSerializeCompact(0, ctType)
	input := append(compact[:len(compact)-1], byte(ctType))
	_, err := verifyCiphertextRun(environment, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on invalid ciphertext size")
	}
}

func TestVerifyCiphertext8(t *testing.T) {
	VerifyCiphertext(t, FheUint8)
}

func TestVerifyCiphertext16(t *testing.T) {
	VerifyCiphertext(t, FheUint16)
}

func TestVerifyCiphertext32(t *testing.T) {
	VerifyCiphertext(t, FheUint32)
}

func TestTrivialEncrypt8(t *testing.T) {
	TrivialEncrypt(t, FheUint8)
}

func TestTrivialEncrypt16(t *testing.T) {
	TrivialEncrypt(t, FheUint16)
}

func TestTrivialEncrypt32(t *testing.T) {
	TrivialEncrypt(t, FheUint32)
}

func TestVerifyCiphertext8BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint8, FheUint16)
	VerifyCiphertextBadType(t, FheUint8, FheUint32)
}

func TestVerifyCiphertext16BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint16, FheUint8)
	VerifyCiphertextBadType(t, FheUint16, FheUint32)
}

func TestVerifyCiphertext32BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint32, FheUint8)
	VerifyCiphertextBadType(t, FheUint32, FheUint16)
}

func TestVerifyCiphertextBadCiphertext(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	_, err := verifyCiphertextRun(environment, addr, addr, make([]byte, 10), readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must fail on bad ciphertext input")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("verifyCiphertext mustn't have verified given ciphertext")
	}
}

func TestFheLibAdd8(t *testing.T) {
	FheLibAdd(t, FheUint8, false)
}

func TestFheLibSub8(t *testing.T) {
	FheLibSub(t, FheUint8, false)
}

func TestFheLibMul8(t *testing.T) {
	FheLibMul(t, FheUint8, false)
}

func TestFheLibLe8(t *testing.T) {
	FheLibLe(t, FheUint8, false)
}

func TestFheLibLt8(t *testing.T) {
	FheLibLt(t, FheUint8, false)
}

func TestFheLibEq8(t *testing.T) {
	FheLibEq(t, FheUint8, false)
}

func TestFheLibGe8(t *testing.T) {
	FheLibGe(t, FheUint8, false)
}

func TestFheLibGt8(t *testing.T) {
	FheLibGt(t, FheUint8, false)
}

func TestFheLibShl8(t *testing.T) {
	FheLibShl(t, FheUint8, false)
}

func TestFheLibShr8(t *testing.T) {
	FheLibShr(t, FheUint8, false)
}

func TestFheLibNe8(t *testing.T) {
	FheLibNe(t, FheUint8, false)
}

func TestFheLibMin8(t *testing.T) {
	FheLibMin(t, FheUint8, false)
}

func TestFheLibMax8(t *testing.T) {
	FheLibMax(t, FheUint8, false)
}

func TestFheLibNeg8(t *testing.T) {
	FheLibNeg(t, FheUint8)
}

func TestFheLibNot8(t *testing.T) {
	FheLibNot(t, FheUint8)
}

func TestFheLibDiv8(t *testing.T) {
	FheLibDiv(t, FheUint8, true)
}

func TestFheLibRem8(t *testing.T) {
	FheLibRem(t, FheUint8, true)
}

func TestFheLibBitAnd8(t *testing.T) {
	FheLibBitAnd(t, FheUint8, false)
}

func TestFheLibBitOr8(t *testing.T) {
	FheLibBitOr(t, FheUint8, false)
}

func TestFheLibBitXor8(t *testing.T) {
	FheLibBitXor(t, FheUint8, false)
}

func TestFheLibRand8(t *testing.T) {
	FheLibRand(t, FheUint8)
}

func TestFheLibTrivialEncrypt8(t *testing.T) {
	LibTrivialEncrypt(t, FheUint8)
}

func TestLibDecrypt8(t *testing.T) {
	LibDecrypt(t, FheUint8)
}

func TestFheAdd8(t *testing.T) {
	FheAdd(t, FheUint8, false)
}

func TestFheAdd16(t *testing.T) {
	FheAdd(t, FheUint16, false)
}

func TestFheAdd32(t *testing.T) {
	FheAdd(t, FheUint32, false)
}

func TestFheScalarAdd8(t *testing.T) {
	FheAdd(t, FheUint8, true)
}

func TestFheScalarAdd16(t *testing.T) {
	FheAdd(t, FheUint16, true)
}

func TestFheScalarAdd32(t *testing.T) {
	FheAdd(t, FheUint32, true)
}

func TestFheSub8(t *testing.T) {
	FheSub(t, FheUint8, false)
}

func TestFheSub16(t *testing.T) {
	FheSub(t, FheUint16, false)
}

func TestFheSub32(t *testing.T) {
	FheSub(t, FheUint32, false)
}

func TestFheScalarSub8(t *testing.T) {
	FheSub(t, FheUint8, true)
}

func TestFheScalarSub16(t *testing.T) {
	FheSub(t, FheUint16, true)
}

func TestFheScalarSub32(t *testing.T) {
	FheSub(t, FheUint32, true)
}

func TestFheMul8(t *testing.T) {
	FheMul(t, FheUint8, false)
}

func TestFheMul16(t *testing.T) {
	FheMul(t, FheUint16, false)
}

func TestFheMul32(t *testing.T) {
	FheMul(t, FheUint32, false)
}

func TestFheScalarMul8(t *testing.T) {
	FheMul(t, FheUint8, true)
}

func TestFheScalarMul16(t *testing.T) {
	FheMul(t, FheUint16, true)
}

func TestFheScalarMul32(t *testing.T) {
	FheMul(t, FheUint32, true)
}

func TestFheDiv8(t *testing.T) {
	FheDiv(t, FheUint8, false)
}

func TestFheDiv16(t *testing.T) {
	FheDiv(t, FheUint16, false)
}

func TestFheDiv32(t *testing.T) {
	FheDiv(t, FheUint32, false)
}

func TestFheScalarDiv8(t *testing.T) {
	FheDiv(t, FheUint8, true)
}

func TestFheScalarDiv16(t *testing.T) {
	FheDiv(t, FheUint16, true)
}

func TestFheScalarDiv32(t *testing.T) {
	FheDiv(t, FheUint32, true)
}

func TestFheRem8(t *testing.T) {
	FheRem(t, FheUint8, false)
}

func TestFheRem16(t *testing.T) {
	FheRem(t, FheUint16, false)
}

func TestFheRem32(t *testing.T) {
	FheRem(t, FheUint32, false)
}

func TestFheScalarRem8(t *testing.T) {
	FheRem(t, FheUint8, true)
}

func TestFheScalarRem16(t *testing.T) {
	FheRem(t, FheUint16, true)
}

func TestFheScalarRem32(t *testing.T) {
	FheRem(t, FheUint32, true)
}

func TestFheBitAnd8(t *testing.T) {
	FheBitAnd(t, FheUint8, false)
}

func TestFheBitAnd16(t *testing.T) {
	FheBitAnd(t, FheUint16, false)
}

func TestFheBitAnd32(t *testing.T) {
	FheBitAnd(t, FheUint32, false)
}

func TestFheScalarBitAnd8(t *testing.T) {
	FheBitAnd(t, FheUint8, true)
}

func TestFheScalarBitAnd16(t *testing.T) {
	FheBitAnd(t, FheUint16, true)
}

func TestFheScalarBitAnd32(t *testing.T) {
	FheBitAnd(t, FheUint32, true)
}

func TestFheBitOr8(t *testing.T) {
	FheBitOr(t, FheUint8, false)
}

func TestFheBitOr16(t *testing.T) {
	FheBitOr(t, FheUint16, false)
}

func TestFheBitOr32(t *testing.T) {
	FheBitOr(t, FheUint32, false)
}

func TestFheScalarBitOr8(t *testing.T) {
	FheBitOr(t, FheUint8, true)
}

func TestFheScalarBitOr16(t *testing.T) {
	FheBitOr(t, FheUint16, true)
}

func TestFheScalarBitOr32(t *testing.T) {
	FheBitOr(t, FheUint32, true)
}

func TestFheBitXor8(t *testing.T) {
	FheBitXor(t, FheUint8, false)
}

func TestFheBitXor16(t *testing.T) {
	FheBitXor(t, FheUint16, false)
}

func TestFheBitXor32(t *testing.T) {
	FheBitXor(t, FheUint32, false)
}

func TestFheScalarBitXor8(t *testing.T) {
	FheBitXor(t, FheUint8, true)
}

func TestFheScalarBitXor16(t *testing.T) {
	FheBitXor(t, FheUint16, true)
}

func TestFheScalarBitXor32(t *testing.T) {
	FheBitXor(t, FheUint32, true)
}

func TestFheShl8(t *testing.T) {
	FheShl(t, FheUint8, false)
}

func TestFheShl16(t *testing.T) {
	FheShl(t, FheUint16, false)
}

func TestFheShl32(t *testing.T) {
	FheShl(t, FheUint32, false)
}

func TestFheScalarShl8(t *testing.T) {
	FheShl(t, FheUint8, true)
}

func TestFheScalarShl16(t *testing.T) {
	FheShl(t, FheUint16, true)
}

func TestFheScalarShl32(t *testing.T) {
	FheShl(t, FheUint32, true)
}

func TestFheShr8(t *testing.T) {
	FheShr(t, FheUint8, false)
}

func TestFheShr16(t *testing.T) {
	FheShr(t, FheUint16, false)
}

func TestFheShr32(t *testing.T) {
	FheShr(t, FheUint32, false)
}

func TestFheScalarShr8(t *testing.T) {
	FheShr(t, FheUint8, true)
}

func TestFheScalarShr16(t *testing.T) {
	FheShr(t, FheUint16, true)
}

func TestFheScalarShr32(t *testing.T) {
	FheShr(t, FheUint32, true)
}

func TestFheEq8(t *testing.T) {
	FheEq(t, FheUint8, false)
}

func TestFheEq16(t *testing.T) {
	FheEq(t, FheUint16, false)
}

func TestFheEq32(t *testing.T) {
	FheEq(t, FheUint32, false)
}

func TestFheScalarEq8(t *testing.T) {
	FheEq(t, FheUint8, true)
}

func TestFheScalarEq16(t *testing.T) {
	FheEq(t, FheUint16, true)
}

func TestFheScalarEq32(t *testing.T) {
	FheEq(t, FheUint32, true)
}

func TestFheNe8(t *testing.T) {
	FheNe(t, FheUint8, false)
}

func TestFheNe16(t *testing.T) {
	FheNe(t, FheUint16, false)
}

func TestFheNe32(t *testing.T) {
	FheNe(t, FheUint32, false)
}

func TestFheScalarNe8(t *testing.T) {
	FheNe(t, FheUint8, true)
}

func TestFheScalarNe16(t *testing.T) {
	FheNe(t, FheUint16, true)
}

func TestFheScalarNe32(t *testing.T) {
	FheNe(t, FheUint32, true)
}

func TestFheGe8(t *testing.T) {
	FheGe(t, FheUint8, false)
}

func TestFheGe16(t *testing.T) {
	FheGe(t, FheUint16, false)
}

func TestFheGe32(t *testing.T) {
	FheGe(t, FheUint32, false)
}

func TestFheScalarGe8(t *testing.T) {
	FheGe(t, FheUint8, true)
}

func TestFheScalarGe16(t *testing.T) {
	FheGe(t, FheUint16, true)
}

func TestFheScalarGe32(t *testing.T) {
	FheGe(t, FheUint32, true)
}

func TestFheGt8(t *testing.T) {
	FheGt(t, FheUint8, false)
}

func TestFheGt16(t *testing.T) {
	FheGt(t, FheUint16, false)
}

func TestFheGt32(t *testing.T) {
	FheGt(t, FheUint32, false)
}

func TestFheScalarGt8(t *testing.T) {
	FheGt(t, FheUint8, true)
}

func TestFheScalarGt16(t *testing.T) {
	FheGt(t, FheUint16, true)
}

func TestFheScalarGt32(t *testing.T) {
	FheGt(t, FheUint32, true)
}

func TestFheLe8(t *testing.T) {
	FheLe(t, FheUint8, false)
}

func TestFheLe16(t *testing.T) {
	FheLe(t, FheUint16, false)
}

func TestFheLe32(t *testing.T) {
	FheLe(t, FheUint32, false)
}

func TestFheScalarLe8(t *testing.T) {
	FheLe(t, FheUint8, true)
}

func TestFheScalarLe16(t *testing.T) {
	FheLe(t, FheUint16, true)
}

func TestFheScalarLe32(t *testing.T) {
	FheLe(t, FheUint32, true)
}

func TestFheLt8(t *testing.T) {
	FheLt(t, FheUint8, false)
}

func TestFheLt16(t *testing.T) {
	FheLt(t, FheUint16, false)
}

func TestFheLt32(t *testing.T) {
	FheLt(t, FheUint32, false)
}

func TestFheScalarLt8(t *testing.T) {
	FheLt(t, FheUint8, true)
}

func TestFheScalarLt16(t *testing.T) {
	FheLt(t, FheUint16, true)
}

func TestFheScalarLt32(t *testing.T) {
	FheLt(t, FheUint32, true)
}

func TestFheMin8(t *testing.T) {
	FheMin(t, FheUint8, false)
}

func TestFheMin16(t *testing.T) {
	FheMin(t, FheUint16, false)
}

func TestFheMin32(t *testing.T) {
	FheMin(t, FheUint32, false)
}

func TestFheScalarMin8(t *testing.T) {
	FheMin(t, FheUint8, true)
}

func TestFheScalarMin16(t *testing.T) {
	FheMin(t, FheUint16, true)
}

func TestFheScalarMin32(t *testing.T) {
	FheMin(t, FheUint32, true)
}

func TestFheMax8(t *testing.T) {
	FheMax(t, FheUint8, false)
}

func TestFheMax16(t *testing.T) {
	FheMax(t, FheUint16, false)
}

func TestFheMax32(t *testing.T) {
	FheMax(t, FheUint32, false)
}

func TestFheNeg8(t *testing.T) {
	FheNeg(t, FheUint8, false)
}

func TestFheNeg16(t *testing.T) {
	FheNeg(t, FheUint16, false)
}

func TestFheNeg32(t *testing.T) {
	FheNeg(t, FheUint32, false)
}

func TestFheNot8(t *testing.T) {
	FheNot(t, FheUint8, false)
}

func TestFheNot16(t *testing.T) {
	FheNot(t, FheUint16, false)
}

func TestFheNot32(t *testing.T) {
	FheNot(t, FheUint32, false)
}

func TestFheScalarMax8(t *testing.T) {
	FheMax(t, FheUint8, true)
}

func TestFheScalarMax16(t *testing.T) {
	FheMax(t, FheUint16, true)
}

func TestFheScalarMax32(t *testing.T) {
	FheMax(t, FheUint32, true)
}

func TestDecrypt8(t *testing.T) {
	Decrypt(t, FheUint8)
}

func TestDecrypt16(t *testing.T) {
	Decrypt(t, FheUint16)
}

func TestDecrypt32(t *testing.T) {
	Decrypt(t, FheUint32)
}

func TestFheRand8(t *testing.T) {
	FheRand(t, FheUint8)
}

func TestFheRand16(t *testing.T) {
	FheRand(t, FheUint16)
}

func TestFheRand32(t *testing.T) {
	FheRand(t, FheUint32)
}

func TestUnknownCiphertextHandle(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	hash := verifyCiphertextInTestMemory(environment, 2, depth, FheUint8).getHash()

	ct := getVerifiedCiphertext(environment, hash)
	if ct == nil {
		t.Fatalf("expected that ciphertext is verified")
	}

	// change the hash
	hash[0]++
	ct = getVerifiedCiphertext(environment, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified")
	}
}

func TestCiphertextNotVerifiedWithoutReturn(t *testing.T) {
	environment := newTestEVMEnvironment()
	environment.depth = 1
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(environment, 1, verifiedDepth, FheUint8).getHash()

	ct := getVerifiedCiphertext(environment, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified")
	}
}

func TestCiphertextNotAutomaticallyDelegated(t *testing.T) {
	environment := newTestEVMEnvironment()
	environment.depth = 3
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(environment, 1, verifiedDepth, FheUint8).getHash()

	ct := getVerifiedCiphertext(environment, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified at depth (%d)", environment.depth)
	}
}

func TestCiphertextVerificationConditions(t *testing.T) {
	environment := newTestEVMEnvironment()
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(environment, 1, verifiedDepth, FheUint8).getHash()

	environment.depth = verifiedDepth
	ctPtr := getVerifiedCiphertext(environment, hash)
	if ctPtr == nil {
		t.Fatalf("expected that ciphertext is verified at verifiedDepth (%d)", verifiedDepth)
	}

	environment.depth = verifiedDepth + 1
	ct := getVerifiedCiphertext(environment, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified at verifiedDepth + 1 (%d)", verifiedDepth+1)
	}

	environment.depth = verifiedDepth - 1
	ct = getVerifiedCiphertext(environment, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified at verifiedDepth - 1 (%d)", verifiedDepth-1)
	}
}

func TestFheRandInvalidInput(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	_, err := fheRandRun(environment, addr, addr, []byte{}, readOnly)
	if err == nil {
		t.Fatalf("fheRand expected failure on invalid type")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on invalid input")
	}
}

func TestFheRandInvalidType(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	_, err := fheRandRun(environment, addr, addr, []byte{byte(254)}, readOnly)
	if err == nil {
		t.Fatalf("fheRand expected failure on invalid type")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on invalid type")
	}
}

func TestFheRandEthCall(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	environment.ethCall = true
	addr := common.Address{}
	readOnly := true
	_, err := fheRandRun(environment, addr, addr, []byte{byte(FheUint8)}, readOnly)
	if err == nil {
		t.Fatalf("fheRand expected failure on EthCall")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on EthCall")
	}
}

func interpreterRunWithStopContract(environment *MockEVMEnvironment, interpreter *vm.EVMInterpreter, contract *vm.Contract, input []byte, readOnly bool) (ret []byte, err error) {
	ret, _ = interpreter.Run(contract, input, readOnly)
	// the following functions are meant to be ran from within interpreter.run so we increment depth to emulate that
	environment.depth++
	RemoveVerifiedCipherextsAtCurrentDepth(environment)
	err = EvalRemOptReqWhenStopToken(environment)
	environment.depth--
	return ret, err
}

func newInterpreterFromEnvironment(environment *MockEVMEnvironment) *vm.EVMInterpreter {
	cfg := vm.Config{}
	evm := &vm.EVM{Config: cfg}
	evm.Context = vm.BlockContext{}
	evm.Context.Transfer = func(vm.StateDB, common.Address, common.Address, *big.Int) {}
	evm.Context.CanTransfer = func(vm.StateDB, common.Address, *big.Int) bool { return true }
	evm.StateDB = environment.stateDb
	interpreter := vm.NewEVMInterpreter(evm)
	return interpreter

}

func newStopOpcodeContract() *vm.Contract {
	addr := vm.AccountRef{}
	c := vm.NewContract(addr, addr, big.NewInt(0), 100000)
	c.Code = make([]byte, 1)
	c.Code[0] = byte(vm.STOP)
	return c
}

func TestLibOneTrueOptimisticRequire(t *testing.T) {
	var value uint64 = 1
	signature := "optimisticRequire(uint256)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	hash := verifyCiphertextInTestMemory(environment, value, depth, FheUint8).getHash()
	input = append(input, signatureBytes...)
	input = append(input, hash.Bytes()...)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}

	interpreter := newInterpreterFromEnvironment(environment)
	// Call the interpreter with a single STOP opcode and expect that the optimistic require doesn't revert.
	out, err = interpreterRunWithStopContract(environment, interpreter, newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestOneFalseOptimisticRequire(t *testing.T) {
	var value uint64 = 0
	depth := 0
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(environment, value, depth, FheUint8).getHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	interpreter := newInterpreterFromEnvironment(environment)
	// Call the interpreter with a single STOP opcode and expect that the optimistic require reverts.
	out, err = interpreterRunWithStopContract(environment, interpreter, newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err == nil || err != ErrExecutionReverted {
		t.Fatalf("require expected reversal on value 0")
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestTwoTrueOptimisticRequires(t *testing.T) {
	var value uint64 = 1
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(environment, value, depth, FheUint8).getHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	hash = verifyCiphertextInTestMemory(environment, value, depth, FheUint8).getHash()
	out, err = optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	interpreter := newInterpreterFromEnvironment(environment)
	// Call the interpreter with a single STOP opcode and expect that the optimistic require doesn't revert.
	out, err = interpreterRunWithStopContract(environment, interpreter, newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestOptimisticRequireTwiceOnSameCiphertext(t *testing.T) {
	var value uint64 = 1
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ct := verifyCiphertextInTestMemory(environment, value, depth, FheUint8)
	hash := ct.getHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	out, err = optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	interpreter := newInterpreterFromEnvironment(environment)
	// Call the interpreter with a single STOP opcode and expect that the optimistic require doesn't revert.
	out, err = interpreterRunWithStopContract(environment, interpreter, newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestOneFalseAndOneTrueOptimisticRequire(t *testing.T) {
	depth := 0
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(environment, 0, depth, FheUint8).getHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	hash = verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).getHash()
	out, err = optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	interpreter := newInterpreterFromEnvironment(environment)
	// Call the interpreter with a single STOP opcode and expect that the optimistic require reverts.
	out, err = interpreterRunWithStopContract(environment, interpreter, newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err == nil || err != ErrExecutionReverted {
		t.Fatalf("require expected reversal on value 0")
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestDecryptWithFalseOptimisticRequire(t *testing.T) {
	depth := 0
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	// Call optimistic require with a false value and expect it succeeds.
	hash := verifyCiphertextInTestMemory(environment, 0, depth, FheUint8).getHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call decrypt and expect it to fail due to the optimistic require being false.
	_, err = decryptRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err == nil {
		t.Fatalf("expected decrypt fails due to false optimistic require")
	}
	// Make sure there are no more optimistic requires after the decrypt call.
	if len(environment.FhevmData().optimisticRequires) != 0 {
		t.Fatalf("expected that there are no optimistic requires after decrypt")
	}
}

func TestDecryptWithTrueOptimisticRequire(t *testing.T) {
	depth := 0
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	// Call optimistic require with a false value and expect it succeeds.
	hash := verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).getHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call decrypt and expect it to succeed due to the optimistic require being true.
	out, err = decryptRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("decrypt expected output len of 32, got %v", len(out))
	}
	// Make sure there are no more optimistic requires after the decrypt call.
	if len(environment.FhevmData().optimisticRequires) != 0 {
		t.Fatalf("expected that there are no optimistic requires after decrypt")
	}
}

func TestDecryptInTransactionDisabled(t *testing.T) {
	depth := 0
	environment := newTestEVMEnvironment()
	environment.depth = depth
	environment.commit = true
	environment.ethCall = false
	environment.fhevmParams.DisableDecryptionsInTransaction = true
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).getHash()
	// Call decrypt and expect it to fail due to disabling of decryptions during commit
	_, err := decryptRun(environment, addr, addr, hash.Bytes(), readOnly)
	if err == nil {
		t.Fatalf("expected to error out in test")
	} else if err.Error() != "decryptions during transaction are disabled" {
		t.Fatalf("unexpected error for disabling decryption transactions, got %s", err.Error())
	}
}
