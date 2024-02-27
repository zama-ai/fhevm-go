package fhevm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
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

func toPrecompileInputNoScalar(isScalar bool, hashes ...common.Hash) []byte {
	ret := make([]byte, 0)
	for _, hash := range hashes {
		ret = append(ret, hash.Bytes()...)
	}
	return ret
}

func evaluateRemainingOptimisticRequiresWithoutKms(environment EVMEnvironment) (bool, error) {
	requires := environment.FhevmData().optimisticRequires
	len := len(requires)
	defer func() { environment.FhevmData().resetOptimisticRequires() }()
	if len != 0 {
		var cumulative *TfheCiphertext = requires[0]
		var err error
		for i := 1; i < len; i++ {
			cumulative, err = cumulative.Bitand(requires[i])
			if err != nil {
				environment.GetLogger().Error("evaluateRemainingOptimisticRequires bitand failed", "err", err)
				return false, err
			}
		}
		result, err := cumulative.Decrypt()
		return result.Uint64() != 0, err
	}
	return true, nil
}

func decryptRunWithoutKms(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	// if not gas estimation and not view function fail if decryptions are disabled in transactions
	if environment.IsCommitting() && !environment.IsEthCall() && environment.FhevmParams().DisableDecryptionsInTransaction {
		msg := "decryptions during transaction are disabled"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	if len(input) != 32 {
		msg := "decrypt input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		msg := "decrypt unverified handle"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip decryption and make sure we return the maximum possible value.
	// We need that, because non-zero bytes cost more than zero bytes in some contexts (e.g. SSTORE or memory operations).
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return bytes.Repeat([]byte{0xFF}, 32), nil
	}
	// Make sure we don't decrypt before any optimistic requires are checked.
	optReqResult, optReqErr := evaluateRemainingOptimisticRequiresWithoutKms(environment)
	if optReqErr != nil {
		return nil, optReqErr
	} else if !optReqResult {
		return nil, ErrExecutionReverted
	}

	plaintext, err := ct.ciphertext.Decrypt()
	if err != nil {
		logger.Error("decrypt failed", "err", err)
		return nil, err
	}

	logger.Info("decrypt success", "plaintext", plaintext)

	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	plaintext.FillBytes(ret)
	return ret, nil
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

// verifyCiphertext expect a certain format: mainly some padding and the size of the buffer
func prepareInputForVerifyCiphertext(input []byte) []byte {
	padding := make([]byte, 60)
	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(input)))
	return append(append(padding, size...), input...)
}

func VerifyCiphertext(t *testing.T, fheUintType FheUintType) {
	var value uint64
	switch fheUintType {
	case FheBool:
		value = 1
	case FheUint4:
		value = 4
	case FheUint8:
		value = 234
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	case FheUint64:
		value = 13333377777777777
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	compact := encryptAndSerializeCompact(value, fheUintType)
	input := prepareInputForVerifyCiphertext(append(compact, byte(fheUintType)))
	out, err := verifyCiphertextRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(TfheCiphertext)
	if err = ct.DeserializeCompact(compact, fheUintType); err != nil {
		t.Fatalf(err.Error())
	}
	if common.BytesToHash(out) != ct.GetHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(environment, ct.GetHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func VerifyCiphertextBadType(t *testing.T, actualType FheUintType, metadataType FheUintType) {
	var value uint64
	switch actualType {
	case FheUint4:
		value = 2
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	case FheUint64:
		value = 13333377777777777
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	compact := encryptAndSerializeCompact(value, actualType)
	input := prepareInputForVerifyCiphertext(append(compact, byte(metadataType)))
	_, err := verifyCiphertextRun(environment, addr, addr, input, readOnly, nil)
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
	case FheUint4:
		value = *big.NewInt(2)
	case FheUint8:
		value = *big.NewInt(2)
	case FheUint16:
		value = *big.NewInt(4283)
	case FheUint32:
		value = *big.NewInt(1333337)
	case FheUint64:
		value = *big.NewInt(13333377777777777)
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	valueBytes := make([]byte, 32)
	input := append(value.FillBytes(valueBytes), byte(fheUintType))
	out, err := trivialEncryptRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(TfheCiphertext).TrivialEncrypt(value, fheUintType)
	if common.BytesToHash(out) != ct.GetHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(environment, ct.GetHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func FheLibAdd(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777

	}
	expected := lhs + rhs
	signature := "fheAdd(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibSub(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}
	expected := lhs - rhs
	signature := "fheSub(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibMul(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 3
		rhs = 2
	case FheUint8:
		lhs = 3
		rhs = 2
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777
		lhs = 1337
	}
	expected := lhs * rhs
	signature := "fheMul(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibLe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 1333777777777
		lhs = 133377777777
	}
	signature := "fheLe(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
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
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLibLt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}

	signature := "fheLt(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
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
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLibEq(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}
	signature := "fheLt(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}
}

func FheLibGe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}
	signature := "fheGe(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
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
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLibGt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}

	signature := "fheGt(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
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
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLibShl(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	case FheUint64:
		lhs = 13333377777777777
		lhs = 34
	}
	expected := lhs << rhs
	signature := "fheShl(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibShr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 3
	case FheUint32:
		lhs = 1333337
		rhs = 3
	case FheUint64:
		lhs = 13333377777777777
		lhs = 34
	}
	expected := lhs >> rhs
	signature := "fheShr(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibNe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}
	signature := "fheNe(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
}

func FheLibMin(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}

	signature := "fheMin(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
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
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != rhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
		}
	}
}

func FheLibMax(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 133377777777
	}

	signature := "fheMax(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
	decrypted, err := res.ciphertext.Decrypt()
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
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != lhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
		}
	}
}

func FheLibNeg(t *testing.T, fheUintType FheUintType) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint4:
		pt = 7
		expected = uint64(16 - uint8(pt))
	case FheUint8:
		pt = 2
		expected = uint64(-uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(-uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(-uint32(pt))
	case FheUint64:
		pt = 13333377777777777
		expected = uint64(-uint64(pt))
	}

	signature := "fheNeg(uint256)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).GetHash()

	input := toLibPrecompileInputNoScalar(signature, ptHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibNot(t *testing.T, fheUintType FheUintType) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint4:
		pt = 5
		expected = uint64(15 - uint8(pt))
	case FheUint8:
		pt = 2
		expected = uint64(^uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(^uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(^uint32(pt))
	case FheUint64:
		pt = 13333377777777777
		expected = uint64(^uint64(pt))
	}

	signature := "fheNot(uint256)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).GetHash()

	input := toLibPrecompileInputNoScalar(signature, ptHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibDiv(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 4
		rhs = 2
	case FheUint8:
		lhs = 4
		rhs = 2
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 137
		rhs = 17
	case FheUint64:
		lhs = 13333377777777777
		lhs = 1337
	}
	expected := lhs / rhs

	signature := "fheDiv(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
		decrypted, err := res.ciphertext.Decrypt()
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
	case FheUint4:
		lhs = 7
		rhs = 3
	case FheUint8:
		lhs = 7
		rhs = 3
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 1337
		rhs = 73
	case FheUint64:
		lhs = 13333377777777777
		lhs = 1337
	}
	expected := lhs % rhs
	signature := "fheRem(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
		decrypted, err := res.ciphertext.Decrypt()
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
	case FheBool:
		lhs = 1
		rhs = 0
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 1337
	}
	expected := lhs & rhs
	signature := "fheBitAnd(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
		decrypted, err := res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibBitOr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheBool:
		lhs = 1
		rhs = 0
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 1337
	}
	expected := lhs | rhs
	signature := "fheBitOr(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
		decrypted, err := res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibBitXor(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheBool:
		lhs = 1
		rhs = 0
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777777777
		lhs = 1337
	}
	expected := lhs ^ rhs
	signature := "fheBitXor(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
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
		decrypted, err := res.ciphertext.Decrypt()
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
	decrypted, err := environment.FhevmData().verifiedCiphertexts[hash].ciphertext.Decrypt()
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !decrypted.IsUint64() {
		t.Fatalf("decrypted value is not 64 bit")
	}
	switch fheUintType {
	case FheUint4:
		if decrypted.Uint64() > 0xF {
			t.Fatalf("random value is bigger than 0xFF (4 bits)")
		}
	case FheUint8:
		if decrypted.Uint64() > 0xFF {
			t.Fatalf("random value is bigger than 0xFF (8 bits)")
		}
	case FheUint16:
		if decrypted.Uint64() > 0xFFFF {
			t.Fatalf("random value is bigger than 0xFFFF (16 bits)")
		}
	case FheUint32:
		if decrypted.Uint64() > 0xFFFFFFFF {
			t.Fatalf("random value is bigger than 0xFFFFFFFF (32 bits)")
		}
	case FheUint64:
		if decrypted.Uint64() > 0xFFFFFFFFFFFFFFFF {
			t.Fatalf("random value is bigger than 0xFFFFFFFFFFFFFFFF (64 bits)")
		}
	}
}

func FheLibRandBounded(t *testing.T, fheUintType FheUintType, upperBound64 uint64) {
	signature := "fheRandBounded(uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	upperBound := uint256.NewInt(upperBound64).Bytes32()
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, upperBound[:]...)
	input = append(input, byte(fheUintType))
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("fheRandBounded expected output len of 32, got %v", len(out))
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 1 {
		t.Fatalf("fheRand expected 1 verified ciphertext")
	}

	hash := common.BytesToHash(out)
	decrypted, err := environment.FhevmData().verifiedCiphertexts[hash].ciphertext.Decrypt()
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !decrypted.IsUint64() {
		t.Fatalf("decrypted value is not 64 bit")
	}
	if decrypted.Uint64() >= upperBound64 {
		t.Fatalf("random value bigger or equal to the upper bound")
	}
}

func FheLibIfThenElse(t *testing.T, fheUintType FheUintType, condition uint64) {
	var second, third uint64
	switch fheUintType {
	case FheUint4:
		second = 2
		third = 1
	case FheUint8:
		second = 2
		third = 1
	case FheUint16:
		second = 4283
		third = 1337
	case FheUint32:
		second = 1333337
		third = 133337
	case FheUint64:
		second = 1333337777777
		third = 133337
	}
	signature := "fheIfThenElse(uint256,uint256,uint256)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	firstHash := verifyCiphertextInTestMemory(environment, condition, depth, FheBool).GetHash()
	secondHash := verifyCiphertextInTestMemory(environment, second, depth, fheUintType).GetHash()
	thirdHash := verifyCiphertextInTestMemory(environment, third, depth, fheUintType).GetHash()
	input := toLibPrecompileInputNoScalar(signature, firstHash, secondHash, thirdHash)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf("VALUE %v", len(input))
		// t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || condition == 1 && decrypted.Uint64() != second || condition == 0 && decrypted.Uint64() != third {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
}

func LibTrivialEncrypt(t *testing.T, fheUintType FheUintType) {
	var value big.Int
	switch fheUintType {
	case FheUint4:
		value = *big.NewInt(2)
	case FheUint8:
		value = *big.NewInt(2)
	case FheUint16:
		value = *big.NewInt(4283)
	case FheUint32:
		value = *big.NewInt(1333337)
	case FheUint64:
		value = *big.NewInt(133333777777)
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
	ct := new(TfheCiphertext).TrivialEncrypt(value, fheUintType)
	if common.BytesToHash(out) != ct.GetHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(environment, ct.GetHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func LibDecrypt(t *testing.T, fheUintType FheUintType) {
	var value uint64
	switch fheUintType {
	case FheUint4:
		value = 2
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	case FheUint64:
		value = 133333777777
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
	hash := verifyCiphertextInTestMemory(environment, value, depth, fheUintType).GetHash()
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

// TODO: can be enabled if mocking kms or running a kms during tests
// func TestLibReencrypt(t *testing.T) {
// 	signature := "reencrypt(uint256,uint256)"
// 	hashRes := crypto.Keccak256([]byte(signature))
// 	signatureBytes := hashRes[0:4]
// 	depth := 1
// 	environment := newTestEVMEnvironment()
// 	environment.depth = depth
// 	environment.ethCall = true
// 	toEncrypt := 7
// 	fheUintType := FheUint8
// 	encCiphertext := verifyCiphertextInTestMemory(environment, uint64(toEncrypt), depth, fheUintType).getHash()
// 	addr := common.Address{}
// 	readOnly := false
// 	input := make([]byte, 0)
// 	input = append(input, signatureBytes...)
// 	input = append(input, encCiphertext.Bytes()...)
// 	// just append twice not to generate public key
// 	input = append(input, encCiphertext.Bytes()...)
// 	_, err := FheLibRun(environment, addr, addr, input, readOnly)
// 	if err != nil {
// 		t.Fatalf("Reencrypt error: %s", err.Error())
// 	}
// }

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
	encCiphertext := verifyCiphertextInTestMemory(environment, uint64(toEncrypt), depth, fheUintType).GetHash()
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
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 133333777777
		rhs = 133337
	}
	expected := lhs + rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheAddRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheSub(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 133333777777
		rhs = 133337
	}
	expected := lhs - rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheSubRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheMul(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 3
	case FheUint8:
		lhs = 2
		rhs = 3
	case FheUint16:
		lhs = 169
		rhs = 5
	case FheUint32:
		lhs = 137
		rhs = 17
	case FheUint64:
		lhs = 137777
		rhs = 17
	}
	expected := lhs * rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheMulRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheDiv(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 6
		rhs = 7
	case FheUint8:
		lhs = 6
		rhs = 7
	case FheUint16:
		lhs = 721
		rhs = 251
	case FheUint32:
		lhs = 137
		rhs = 65521
	case FheUint64:
		lhs = 137777777
		rhs = 65521
	}
	expected := lhs / rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheDivRun(environment, addr, addr, input, readOnly, nil)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.Decrypt()
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
	case FheUint4:
		lhs = 9
		rhs = 5
	case FheUint8:
		lhs = 9
		rhs = 5
	case FheUint16:
		lhs = 1773
		rhs = 523
	case FheUint32:
		lhs = 123765
		rhs = 2179
	case FheUint64:
		lhs = 1237651337
		rhs = 2179
	}
	expected := lhs % rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheRemRun(environment, addr, addr, input, readOnly, nil)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.Decrypt()
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
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}
	expected := lhs & rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheBitAndRun(environment, addr, addr, input, readOnly, nil)
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
		decrypted, err := res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheBitOr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}
	expected := lhs | rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheBitOrRun(environment, addr, addr, input, readOnly, nil)
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
		decrypted, err := res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheBitXor(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}
	expected := lhs ^ rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheBitXorRun(environment, addr, addr, input, readOnly, nil)
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
		decrypted, err := res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheShl(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	case FheUint64:
		lhs = 1333337777
		rhs = 10
	}
	expected := lhs << rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheShlRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheShr(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 3
	case FheUint32:
		lhs = 1333337
		rhs = 3
	case FheUint64:
		lhs = 133333777777
		rhs = 10
	}
	expected := lhs >> rhs
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheShrRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheEq(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	// lhs == rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheEqRun(environment, addr, addr, input1, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}
}

func FheNe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	// lhs == rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheNeRun(environment, addr, addr, input1, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
}

func FheGe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	// lhs >= rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheGeRun(environment, addr, addr, input1, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs >= lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheGeRun(environment, addr, addr, input2, readOnly, nil)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheGt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}
	// lhs > rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheGtRun(environment, addr, addr, input1, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs > lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheGtRun(environment, addr, addr, input2, readOnly, nil)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLe(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 1333337777
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}

	// lhs <= rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheLeRun(environment, addr, addr, input1, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs <= lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheLeRun(environment, addr, addr, input2, readOnly, nil)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLt(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}

	// lhs < rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheLtRun(environment, addr, addr, input1, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs < lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheLtRun(environment, addr, addr, input2, readOnly, nil)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheMin(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 133333777777
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}

	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheMinRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != rhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheMinRun(environment, addr, addr, input2, readOnly, nil)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != rhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
		}
	}
}

func FheMax(t *testing.T, fheUintType FheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()
	}

	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := fheMaxRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != lhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = fheMaxRun(environment, addr, addr, input2, readOnly, nil)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.Decrypt()
		if err != nil || decrypted.Uint64() != lhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
		}
	}
}

func FheNeg(t *testing.T, fheUintType FheUintType, scalar bool) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint4:
		pt = 2
		expected = uint64(-uint8(pt))
	case FheUint8:
		pt = 2
		expected = uint64(-uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(-uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(-uint32(pt))
	case FheUint64:
		pt = 133333777777
		expected = uint64(-uint64(pt))
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).GetHash()

	input := make([]byte, 0)
	input = append(input, ptHash.Bytes()...)
	out, err := fheNegRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheNot(t *testing.T, fheUintType FheUintType, scalar bool) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint4:
		pt = 2
		expected = uint64(^uint8(pt))
	case FheUint8:
		pt = 2
		expected = uint64(^uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(^uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(^uint32(pt))
	case FheUint64:
		pt = 1333337777777
		expected = uint64(^uint64(pt))
	}

	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(environment, pt, depth, fheUintType).GetHash()

	input := make([]byte, 0)
	input = append(input, ptHash.Bytes()...)
	out, err := fheNotRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheIfThenElse(t *testing.T, fheUintType FheUintType, condition uint64) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint4:
		lhs = 2
		rhs = 1
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	case FheUint64:
		lhs = 13333377777
		rhs = 133337
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	conditionHash := verifyCiphertextInTestMemory(environment, condition, depth, FheBool).GetHash()
	lhsHash := verifyCiphertextInTestMemory(environment, lhs, depth, fheUintType).GetHash()
	rhsHash := verifyCiphertextInTestMemory(environment, rhs, depth, fheUintType).GetHash()

	input1 := toPrecompileInputNoScalar(false, conditionHash, lhsHash, rhsHash)
	out, err := fheIfThenElseRun(environment, addr, addr, input1, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.Decrypt()
	if err != nil || condition == 1 && decrypted.Uint64() != lhs || condition == 0 && decrypted.Uint64() != rhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}
}

func Decrypt(t *testing.T, fheUintType FheUintType) {
	var value uint64
	switch fheUintType {
	case FheUint4:
		value = 2
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	case FheUint64:
		value = 133333777777777
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(environment, value, depth, fheUintType).GetHash()
	out, err := decryptRunWithoutKms(environment, addr, addr, hash.Bytes(), readOnly)
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
	out, err := fheRandRun(environment, addr, addr, []byte{byte(fheUintType)}, readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("fheRand expected output len of 32, got %v", len(out))
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 1 {
		t.Fatalf("fheRand expected 1 verified ciphertext")
	}

	hash := common.BytesToHash(out)
	_, err = environment.FhevmData().verifiedCiphertexts[hash].ciphertext.Decrypt()
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
	compact := encryptAndSerializeCompact(0, FheUint64)
	input := prepareInputForVerifyCiphertext(append(compact, byte(invalidType)))
	_, err := verifyCiphertextRun(environment, addr, addr, input, readOnly, nil)
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
	trivialEncryptRun(environment, addr, addr, input, readOnly, nil)
}

func TestCastInvalidType(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := FheUintType(255)
	hash := verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).GetHash()
	input := make([]byte, 0)
	input = append(input, hash.Bytes()...)
	input = append(input, byte(invalidType))
	_, err := castRun(environment, addr, addr, input, readOnly, nil)
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
	input := prepareInputForVerifyCiphertext(append(compact[:len(compact)-1], byte(ctType)))
	_, err := verifyCiphertextRun(environment, addr, addr, input, readOnly, nil)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on invalid ciphertext size")
	}
}

func TestVerifyCiphertext4(t *testing.T) {
	VerifyCiphertext(t, FheUint4)
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

func TestVerifyCiphertext64(t *testing.T) {
	VerifyCiphertext(t, FheUint64)
}

func TestTrivialEncrypt4(t *testing.T) {
	TrivialEncrypt(t, FheUint4)
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

func TestTrivialEncrypt64(t *testing.T) {
	TrivialEncrypt(t, FheUint64)
}

func TestVerifyCiphertext4BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint4, FheUint8)
	VerifyCiphertextBadType(t, FheUint4, FheUint16)
	VerifyCiphertextBadType(t, FheUint4, FheUint32)
	VerifyCiphertextBadType(t, FheUint4, FheUint64)
}

func TestVerifyCiphertext8BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint8, FheUint4)
	VerifyCiphertextBadType(t, FheUint8, FheUint16)
	VerifyCiphertextBadType(t, FheUint8, FheUint32)
	VerifyCiphertextBadType(t, FheUint8, FheUint64)
}

func TestVerifyCiphertext16BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint16, FheUint4)
	VerifyCiphertextBadType(t, FheUint16, FheUint8)
	VerifyCiphertextBadType(t, FheUint16, FheUint32)
	VerifyCiphertextBadType(t, FheUint16, FheUint64)
}

func TestVerifyCiphertext32BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint32, FheUint4)
	VerifyCiphertextBadType(t, FheUint32, FheUint8)
	VerifyCiphertextBadType(t, FheUint32, FheUint16)
	VerifyCiphertextBadType(t, FheUint32, FheUint64)
}

func TestVerifyCiphertext64BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint64, FheUint4)
	VerifyCiphertextBadType(t, FheUint64, FheUint8)
	VerifyCiphertextBadType(t, FheUint64, FheUint16)
	VerifyCiphertextBadType(t, FheUint64, FheUint32)
}

func TestVerifyCiphertextBadCiphertext(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	input := prepareInputForVerifyCiphertext(make([]byte, 10))
	_, err := verifyCiphertextRun(environment, addr, addr, input, readOnly, nil)
	if err == nil {
		t.Fatalf("verifyCiphertext must fail on bad ciphertext input")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("verifyCiphertext mustn't have verified given ciphertext")
	}
}

func TestFheLibBitAndBool(t *testing.T) {
	FheLibBitAnd(t, FheBool, false)
}

func TestFheLibBitOrBool(t *testing.T) {
	FheLibBitOr(t, FheBool, false)
}

func TestFheLibBitXorBool(t *testing.T) {
	FheLibBitXor(t, FheBool, false)
}

func TestFheLibAdd4(t *testing.T) {
	FheLibAdd(t, FheUint4, false)
}

func TestFheLibSub4(t *testing.T) {
	FheLibSub(t, FheUint4, false)
}

func TestFheLibMul4(t *testing.T) {
	FheLibMul(t, FheUint4, false)
}

func TestFheLibLe4(t *testing.T) {
	FheLibLe(t, FheUint4, false)
}

func TestFheLibLt4(t *testing.T) {
	FheLibLt(t, FheUint4, false)
}

func TestFheLibEq4(t *testing.T) {
	FheLibEq(t, FheUint4, false)
}

func TestFheLibGe4(t *testing.T) {
	FheLibGe(t, FheUint4, false)
}

func TestFheLibGt4(t *testing.T) {
	FheLibGt(t, FheUint4, false)
}

func TestFheLibShl4(t *testing.T) {
	FheLibShl(t, FheUint4, false)
}

func TestFheLibShr4(t *testing.T) {
	FheLibShr(t, FheUint4, false)
}

func TestFheLibNe4(t *testing.T) {
	FheLibNe(t, FheUint4, false)
}

func TestFheLibMin4(t *testing.T) {
	FheLibMin(t, FheUint4, false)
}

func TestFheLibMax4(t *testing.T) {
	FheLibMax(t, FheUint4, false)
}

func TestFheLibNeg4(t *testing.T) {
	FheLibNeg(t, FheUint4)
}

func TestFheLibNot4(t *testing.T) {
	FheLibNot(t, FheUint4)
}

func TestFheLibDiv4(t *testing.T) {
	FheLibDiv(t, FheUint4, true)
}

func TestFheLibRem4(t *testing.T) {
	FheLibRem(t, FheUint4, true)
}

func TestFheLibBitAnd4(t *testing.T) {
	FheLibBitAnd(t, FheUint4, false)
}

func TestFheLibBitOr4(t *testing.T) {
	FheLibBitOr(t, FheUint4, false)
}

func TestFheLibBitXor4(t *testing.T) {
	FheLibBitXor(t, FheUint4, false)
}

func TestFheLibRand4(t *testing.T) {
	FheLibRand(t, FheUint4)
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

func TestFheLibRand16(t *testing.T) {
	FheLibRand(t, FheUint16)
}

func TestFheLibRand32(t *testing.T) {
	FheLibRand(t, FheUint32)
}

func TestFheLibRand64(t *testing.T) {
	FheLibRand(t, FheUint64)
}

func TestFheLibRandBounded8(t *testing.T) {
	FheLibRandBounded(t, FheUint8, 8)
}

func TestFheLibRandBounded16(t *testing.T) {
	FheLibRandBounded(t, FheUint16, 16)
}

func TestFheLibRandBounded32(t *testing.T) {
	FheLibRandBounded(t, FheUint32, 32)
}

func TestFheLibRandBounded64(t *testing.T) {
	FheLibRandBounded(t, FheUint64, 64)
}

func TestFheLibIfThenElse8(t *testing.T) {
	FheLibIfThenElse(t, FheUint8, 1)
	FheLibIfThenElse(t, FheUint8, 0)
}

func TestFheLibIfThenElse16(t *testing.T) {
	FheLibIfThenElse(t, FheUint16, 1)
	FheLibIfThenElse(t, FheUint16, 0)
}

func TestFheLibIfThenElse32(t *testing.T) {
	FheLibIfThenElse(t, FheUint32, 1)
	FheLibIfThenElse(t, FheUint32, 0)
}

func TestFheLibIfThenElse64(t *testing.T) {
	FheLibIfThenElse(t, FheUint64, 1)
	FheLibIfThenElse(t, FheUint64, 0)
}

func TestFheLibTrivialEncrypt8(t *testing.T) {
	LibTrivialEncrypt(t, FheUint8)
}

// TODO: can be enabled if mocking kms or running a kms during tests
// func TestLibDecrypt8(t *testing.T) {
// 	LibDecrypt(t, FheUint8)
// }

func TestFheAdd8(t *testing.T) {
	FheAdd(t, FheUint8, false)
}

func TestFheAdd16(t *testing.T) {
	FheAdd(t, FheUint16, false)
}

func TestFheAdd32(t *testing.T) {
	FheAdd(t, FheUint32, false)
}

func TestFheAdd64(t *testing.T) {
	FheAdd(t, FheUint64, false)
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

func TestFheScalarAdd64(t *testing.T) {
	FheAdd(t, FheUint64, true)
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

func TestFheSub64(t *testing.T) {
	FheSub(t, FheUint64, false)
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

func TestFheScalarSub64(t *testing.T) {
	FheSub(t, FheUint64, true)
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

func TestFheMul64(t *testing.T) {
	FheMul(t, FheUint64, false)
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

func TestFheScalarMul64(t *testing.T) {
	FheMul(t, FheUint64, true)
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

func TestFheDiv64(t *testing.T) {
	FheDiv(t, FheUint64, false)
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

func TestFheScalarDiv64(t *testing.T) {
	FheDiv(t, FheUint64, true)
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

func TestFheRem64(t *testing.T) {
	FheRem(t, FheUint64, false)
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

func TestFheScalarRem64(t *testing.T) {
	FheRem(t, FheUint64, true)
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

func TestFheBitAnd64(t *testing.T) {
	FheBitAnd(t, FheUint64, false)
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

func TestFheScalarBitAnd64(t *testing.T) {
	FheBitAnd(t, FheUint64, true)
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

func TestFheBitOr64(t *testing.T) {
	FheBitOr(t, FheUint64, false)
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

func TestFheScalarBitOr64(t *testing.T) {
	FheBitOr(t, FheUint64, true)
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

func TestFheBitXor64(t *testing.T) {
	FheBitXor(t, FheUint64, false)
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

func TestFheScalarBitXor64(t *testing.T) {
	FheBitXor(t, FheUint64, true)
}

func TestFheShl4(t *testing.T) {
	FheShl(t, FheUint4, false)
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

func TestFheShl64(t *testing.T) {
	FheShl(t, FheUint64, false)
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

func TestFheScalarShl64(t *testing.T) {
	FheShl(t, FheUint64, true)
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

func TestFheShr64(t *testing.T) {
	FheShr(t, FheUint64, false)
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

func TestFheScalarShr64(t *testing.T) {
	FheShr(t, FheUint64, true)
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

func TestFheEq64(t *testing.T) {
	FheEq(t, FheUint64, false)
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

func TestFheScalarEq64(t *testing.T) {
	FheEq(t, FheUint64, true)
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

func TestFheNe64(t *testing.T) {
	FheNe(t, FheUint64, false)
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

func TestFheScalarNe64(t *testing.T) {
	FheNe(t, FheUint64, true)
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

func TestFheGe64(t *testing.T) {
	FheGe(t, FheUint64, false)
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

func TestFheScalarGe64(t *testing.T) {
	FheGe(t, FheUint64, true)
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

func TestFheGt64(t *testing.T) {
	FheGt(t, FheUint64, false)
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

func TestFheScalarGt64(t *testing.T) {
	FheGt(t, FheUint64, true)
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

func TestFheLe64(t *testing.T) {
	FheLe(t, FheUint64, false)
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

func TestFheScalarLe64(t *testing.T) {
	FheLe(t, FheUint64, true)
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

func TestFheLt64(t *testing.T) {
	FheLt(t, FheUint64, false)
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

func TestFheScalarLt64(t *testing.T) {
	FheLt(t, FheUint64, true)
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

func TestFheMin64(t *testing.T) {
	FheMin(t, FheUint64, false)
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

func TestFheScalarMin64(t *testing.T) {
	FheMin(t, FheUint64, true)
}

func TestFheMax4(t *testing.T) {
	FheMax(t, FheUint4, false)
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

func TestFheMax64(t *testing.T) {
	FheMax(t, FheUint64, false)
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

func TestFheNeg64(t *testing.T) {
	FheNeg(t, FheUint64, false)
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

func TestFheNot64(t *testing.T) {
	FheNot(t, FheUint64, false)
}

func TestFheIfThenElse4(t *testing.T) {
	FheIfThenElse(t, FheUint4, 1)
	FheIfThenElse(t, FheUint4, 0)
}

func TestFheIfThenElse8(t *testing.T) {
	FheIfThenElse(t, FheUint8, 1)
	FheIfThenElse(t, FheUint8, 0)
}

func TestFheIfThenElse16(t *testing.T) {
	FheIfThenElse(t, FheUint16, 1)
	FheIfThenElse(t, FheUint16, 0)
}

func TestFheIfThenElse32(t *testing.T) {
	FheIfThenElse(t, FheUint32, 1)
	FheIfThenElse(t, FheUint32, 0)
}

func TestFheIfThenElse64(t *testing.T) {
	FheIfThenElse(t, FheUint64, 1)
	FheIfThenElse(t, FheUint64, 0)
}

func TestFheScalarMax4(t *testing.T) {
	FheMax(t, FheUint4, true)
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

func TestFheScalarMax64(t *testing.T) {
	FheMax(t, FheUint64, true)
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

func TestDecrypt64(t *testing.T) {
	Decrypt(t, FheUint64)
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

func TestFheRand64(t *testing.T) {
	FheRand(t, FheUint64)
}

func TestUnknownCiphertextHandle(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	hash := verifyCiphertextInTestMemory(environment, 2, depth, FheUint8).GetHash()

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
	hash := verifyCiphertextInTestMemory(environment, 1, verifiedDepth, FheUint8).GetHash()

	ct := getVerifiedCiphertext(environment, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified")
	}
}

func TestCiphertextNotAutomaticallyDelegated(t *testing.T) {
	environment := newTestEVMEnvironment()
	environment.depth = 3
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(environment, 1, verifiedDepth, FheUint8).GetHash()

	ct := getVerifiedCiphertext(environment, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified at depth (%d)", environment.depth)
	}
}

func TestCiphertextVerificationConditions(t *testing.T) {
	environment := newTestEVMEnvironment()
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(environment, 1, verifiedDepth, FheUint8).GetHash()

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
	_, err := fheRandRun(environment, addr, addr, []byte{}, readOnly, nil)
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
	_, err := fheRandRun(environment, addr, addr, []byte{byte(254)}, readOnly, nil)
	if err == nil {
		t.Fatalf("fheRand expected failure on invalid type")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on invalid type")
	}
}

func TestFheRandBoundedInvalidType(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	upperBound := uint256.NewInt(8).Bytes32()
	input = append(input, upperBound[:]...)
	input = append(input, byte(254))
	_, err := fheRandBoundedRun(environment, addr, addr, input, readOnly, nil)
	if err == nil {
		t.Fatalf("fheRandBounded expected failure on invalid type")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRandBounded expected 0 verified ciphertexts on invalid type")
	}
}

func FheRandBoundedInvalidBound(t *testing.T, fheUintType FheUintType, bound *uint256.Int) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	upperBound := bound.Bytes32()
	input = append(input, upperBound[:]...)
	input = append(input, byte(fheUintType))
	_, err := fheRandBoundedRun(environment, addr, addr, input, readOnly, nil)
	if err == nil {
		t.Fatalf("fheRandBounded expected failure on invalid bound")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRandBounded expected 0 verified ciphertexts on invalid bound")
	}
}

func TestFheRandBoundedInvalidBound8(t *testing.T) {
	FheRandBoundedInvalidBound(t, FheUint8, uint256.NewInt(0))
	FheRandBoundedInvalidBound(t, FheUint8, uint256.NewInt(3))
	FheRandBoundedInvalidBound(t, FheUint8, uint256.NewInt(98))
	FheRandBoundedInvalidBound(t, FheUint8, uint256.NewInt(0xFF))
	moreThan64Bits := uint256.NewInt(0xFFFFFFFFFFFFFFFF)
	moreThan64Bits.Add(moreThan64Bits, uint256.NewInt(1))
	FheRandBoundedInvalidBound(t, FheUint8, moreThan64Bits)
}

func TestFheRandBoundedInvalidBound16(t *testing.T) {
	FheRandBoundedInvalidBound(t, FheUint16, uint256.NewInt(0))
	FheRandBoundedInvalidBound(t, FheUint16, uint256.NewInt(999))
	FheRandBoundedInvalidBound(t, FheUint16, uint256.NewInt(448))
	FheRandBoundedInvalidBound(t, FheUint16, uint256.NewInt(0xFFFF))
	moreThan64Bits := uint256.NewInt(0xFFFFFFFFFFFFFFFF)
	moreThan64Bits.Add(moreThan64Bits, uint256.NewInt(1))
	FheRandBoundedInvalidBound(t, FheUint16, moreThan64Bits)
}

func TestFheRandBoundedInvalidBound32(t *testing.T) {
	FheRandBoundedInvalidBound(t, FheUint32, uint256.NewInt(0))
	FheRandBoundedInvalidBound(t, FheUint32, uint256.NewInt(111999))
	FheRandBoundedInvalidBound(t, FheUint32, uint256.NewInt(448884))
	FheRandBoundedInvalidBound(t, FheUint32, uint256.NewInt(0xFFFFFFFF))
	moreThan64Bits := uint256.NewInt(0xFFFFFFFFFFFFFFFF)
	moreThan64Bits.Add(moreThan64Bits, uint256.NewInt(1))
	FheRandBoundedInvalidBound(t, FheUint32, moreThan64Bits)
}

func TestFheRandBoundedInvalidBound64(t *testing.T) {
	FheRandBoundedInvalidBound(t, FheUint64, uint256.NewInt(0))
	FheRandBoundedInvalidBound(t, FheUint64, uint256.NewInt(111999))
	FheRandBoundedInvalidBound(t, FheUint64, uint256.NewInt(448884))
	FheRandBoundedInvalidBound(t, FheUint64, uint256.NewInt(0xFFFFFFFFFFFFFFFF))
	moreThan64Bits := uint256.NewInt(0xFFFFFFFFFFFFFFFF)
	moreThan64Bits.Add(moreThan64Bits, uint256.NewInt(1))
	FheRandBoundedInvalidBound(t, FheUint32, moreThan64Bits)
}

func TestFheRandEthCall(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	environment.ethCall = true
	addr := common.Address{}
	readOnly := true
	_, err := fheRandRun(environment, addr, addr, []byte{byte(FheUint8)}, readOnly, nil)
	if err == nil {
		t.Fatalf("fheRand expected failure on EthCall")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on EthCall")
	}
}

func TestFheRandBoundedEthCall(t *testing.T) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	environment.ethCall = true
	addr := common.Address{}
	readOnly := true
	input := make([]byte, 0)
	upperBound := uint256.NewInt(4).Bytes32()
	input = append(input, upperBound[:]...)
	input = append(input, byte(FheUint8))
	_, err := fheRandBoundedRun(environment, addr, addr, input, readOnly, nil)
	if err == nil {
		t.Fatalf("fheRandBounded expected failure on EthCall")
	}
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("fheRandBounded expected 0 verified ciphertexts on EthCall")
	}
}

func EvalRemOptReqWhenStopTokenWithoutKms(env EVMEnvironment) (err error) {
	err = nil
	// If we are finishing execution (about to go to from depth 1 to depth 0), evaluate
	// any remaining optimistic requires.
	if env.GetDepth() == 1 {
		result, evalErr := evaluateRemainingOptimisticRequiresWithoutKms(env)
		if evalErr != nil {
			err = evalErr
		} else if !result {
			err = ErrExecutionReverted
		}
	}
	return err
}

func interpreterRunWithStopContract(environment *MockEVMEnvironment, interpreter *vm.EVMInterpreter, contract *vm.Contract, input []byte, readOnly bool) (ret []byte, err error) {
	ret, _ = interpreter.Run(contract, input, readOnly)
	// the following functions are meant to be ran from within interpreter.run so we increment depth to emulate that
	environment.depth++
	RemoveVerifiedCipherextsAtCurrentDepth(environment)
	err = EvalRemOptReqWhenStopTokenWithoutKms(environment)
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
	hash := verifyCiphertextInTestMemory(environment, value, depth, FheUint8).GetHash()
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
	hash := verifyCiphertextInTestMemory(environment, value, depth, FheUint8).GetHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
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
	hash := verifyCiphertextInTestMemory(environment, value, depth, FheUint8).GetHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	hash = verifyCiphertextInTestMemory(environment, value, depth, FheUint8).GetHash()
	out, err = optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
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
	hash := ct.GetHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	out, err = optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
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
	hash := verifyCiphertextInTestMemory(environment, 0, depth, FheUint8).GetHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	hash = verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).GetHash()
	out, err = optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
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
	hash := verifyCiphertextInTestMemory(environment, 0, depth, FheUint8).GetHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call decrypt and expect it to fail due to the optimistic require being false.
	_, err = decryptRunWithoutKms(environment, addr, addr, hash.Bytes(), readOnly)
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
	hash := verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).GetHash()
	out, err := optimisticRequireRun(environment, addr, addr, hash.Bytes(), readOnly, nil)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call decrypt and expect it to succeed due to the optimistic require being true.
	out, err = decryptRunWithoutKms(environment, addr, addr, hash.Bytes(), readOnly)
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
	hash := verifyCiphertextInTestMemory(environment, 1, depth, FheUint8).GetHash()
	// Call decrypt and expect it to fail due to disabling of decryptions during commit
	_, err := decryptRunWithoutKms(environment, addr, addr, hash.Bytes(), readOnly)
	if err == nil {
		t.Fatalf("expected to error out in test")
	} else if err.Error() != "decryptions during transaction are disabled" {
		t.Fatalf("unexpected error for disabling decryption transactions, got %s", err.Error())
	}
}

func TestFheLibGetCiphertextInvalidInputSize(t *testing.T) {
	environment := newTestEVMEnvironment()
	addr := common.Address{}
	environment.ethCall = true
	readOnly := true
	input := make([]byte, 0)
	zeroPadding := make([]byte, 12)
	signature := crypto.Keccak256([]byte("getCiphertext(address,uint256)"))[0:4]
	input = append(input, signature...)
	input = append(input, zeroPadding...)
	// missing input data...
	_, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("getCiphertext expected failure on bad input size")
	}
}

func TestFheLibGetCiphertextNonEthCall(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 1
	environment.depth = depth
	plaintext := uint64(2)
	ct := verifyCiphertextInTestMemory(environment, plaintext, depth, FheUint32)
	ctHash := ct.GetHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256FromBig(ctHash.Big())

	// Setup and call SSTORE - it requires a location and a value to set there.
	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Call getCiphertext.
	addr := common.Address{}
	environment.ethCall = false
	readOnly := true
	input := make([]byte, 0)
	zeroPadding := make([]byte, 12)
	signature := crypto.Keccak256([]byte("getCiphertext(address,uint256)"))[0:4]
	input = append(input, signature...)
	input = append(input, zeroPadding...)
	input = append(input, testContractAddress{}.Address().Bytes()...)
	input = append(input, ctHash.Bytes()...)
	_, err = FheLibRun(environment, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("getCiphertext expected failure non-EthCall")
	}
}

func TestFheLibGetCiphertextNonExistentHandle(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 1
	environment.depth = depth
	plaintext := uint64(2)
	ct := verifyCiphertextInTestMemory(environment, plaintext, depth, FheUint32)
	ctHash := ct.GetHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256FromBig(ctHash.Big())

	// Setup and call SSTORE - it requires a location and a value to set there.
	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Change ctHash to something that doesn't exist
	ctHash[0]++

	// Call getCiphertext.
	addr := common.Address{}
	environment.ethCall = true
	readOnly := true
	input := make([]byte, 0)
	zeroPadding := make([]byte, 12)
	signature := crypto.Keccak256([]byte("getCiphertext(address,uint256)"))[0:4]
	input = append(input, signature...)
	input = append(input, zeroPadding...)
	input = append(input, testContractAddress{}.Address().Bytes()...)
	input = append(input, ctHash.Bytes()...)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if len(out) != 0 {
		t.Fatalf("getCiphertext expected empty output on non-existent handle")
	}
}

func TestFheLibGetCiphertextWrongContractAddress(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 1
	environment.depth = depth
	plaintext := uint64(2)
	ct := verifyCiphertextInTestMemory(environment, plaintext, depth, FheUint32)
	ctHash := ct.GetHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256FromBig(ctHash.Big())

	// Setup and call SSTORE - it requires a location and a value to set there.
	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Call getCiphertext.
	addr := common.Address{}
	environment.ethCall = true
	readOnly := true
	contractAddress := testContractAddress{}.Address()
	// Change address to another one that doesn't contain the handle.
	contractAddress[0]++
	input := make([]byte, 0)
	zeroPadding := make([]byte, 12)
	signature := crypto.Keccak256([]byte("getCiphertext(address,uint256)"))[0:4]
	input = append(input, signature...)
	input = append(input, zeroPadding...)
	input = append(input, contractAddress.Bytes()...)
	input = append(input, ctHash.Bytes()...)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if len(out) != 0 {
		t.Fatalf("getCiphertext expected empty output on wrong contract address")
	}
}

func FheLibGetCiphertext(t *testing.T, fheUintType FheUintType) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 1
	environment.depth = depth
	plaintext := uint64(2)
	ct := verifyCiphertextInTestMemory(environment, plaintext, depth, fheUintType)
	ctHash := ct.GetHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256FromBig(ctHash.Big())

	// Setup and call SSTORE - it requires a location and a value to set there.
	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Call getCiphertext.
	addr := common.Address{}
	environment.ethCall = true
	readOnly := true
	input := make([]byte, 0)
	zeroPadding := make([]byte, 12)
	signature := crypto.Keccak256([]byte("getCiphertext(address,uint256)"))[0:4]
	input = append(input, signature...)
	input = append(input, zeroPadding...)
	input = append(input, testContractAddress{}.Address().Bytes()...)
	input = append(input, ctHash.Bytes()...)
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	size, _ := GetExpandedFheCiphertextSize(fheUintType)
	if size != uint(len(out)) {
		t.Fatalf("getCiphertext returned ciphertext size of %d, expected %d", len(out), size)
	}

	outCt := new(TfheCiphertext)
	err = outCt.Deserialize(out, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}
	decrypted, err := outCt.Decrypt()
	if err != nil {
		t.Fatalf(err.Error())
	}
	if decrypted.Uint64() != plaintext {
		t.Fatalf("getCiphertext returned ciphertext value of %d, expected %d", decrypted.Uint64(), plaintext)
	}
}

func TestFheLibGetCiphertext8(t *testing.T) {
	FheLibGetCiphertext(t, FheUint8)
}

func TestFheLibGetCiphertext16(t *testing.T) {
	FheLibGetCiphertext(t, FheUint16)
}

func TestFheLibGetCiphertext32(t *testing.T) {
	FheLibGetCiphertext(t, FheUint32)
}

func TestFheLibGetCiphertext64(t *testing.T) {
	FheLibGetCiphertext(t, FheUint64)
}
