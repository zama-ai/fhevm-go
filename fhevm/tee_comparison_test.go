package fhevm

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
)

func TestTeeLeRun(t *testing.T) {
	signature := "teeLe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected bool
	}{
		{tfhe.FheUint4, 2, 1, false},
		{tfhe.FheUint8, 2, 1, false},
		{tfhe.FheUint16, 4283, 1337, false},
		{tfhe.FheUint32, 1333337, 1337, false},
		{tfhe.FheUint64, 13333377777777777, 133377777777, false},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeLe with %s", tc.typ), func(t *testing.T) {
			teeComparison1Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeLtRun(t *testing.T) {
	signature := "teeLt(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected bool
	}{
		{tfhe.FheUint4, 2, 1, false},
		{tfhe.FheUint8, 2, 1, false},
		{tfhe.FheUint16, 4283, 1337, false},
		{tfhe.FheUint32, 1333337, 1337, false},
		{tfhe.FheUint64, 13333377777777777, 133377777777, false},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeLt with %s", tc.typ), func(t *testing.T) {
			teeComparison1Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeEqRun(t *testing.T) {
	signature := "teeEq(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected bool
	}{
		{tfhe.FheUint4, 2, 1, false},
		{tfhe.FheUint8, 2, 1, false},
		{tfhe.FheUint16, 4283, 1337, false},
		{tfhe.FheUint32, 1333337, 1337, false},
		{tfhe.FheUint64, 13333377777777777, 133377777777, false},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeEq with %s", tc.typ), func(t *testing.T) {
			teeComparison1Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeGeRun(t *testing.T) {
	signature := "teeGe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected bool
	}{
		{tfhe.FheUint4, 2, 1, true},
		{tfhe.FheUint8, 2, 1, true},
		{tfhe.FheUint16, 4283, 1337, true},
		{tfhe.FheUint32, 1333337, 1337, true},
		{tfhe.FheUint64, 13333377777777777, 133377777777, true},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeGe with %s", tc.typ), func(t *testing.T) {
			teeComparison1Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeGtRun(t *testing.T) {
	signature := "teeGt(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected bool
	}{
		{tfhe.FheUint4, 2, 1, true},
		{tfhe.FheUint8, 2, 1, true},
		{tfhe.FheUint16, 4283, 1337, true},
		{tfhe.FheUint32, 1333337, 1337, true},
		{tfhe.FheUint64, 13333377777777777, 133377777777, true},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeGt with %s", tc.typ), func(t *testing.T) {
			teeComparison1Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeNeRun(t *testing.T) {
	signature := "teeNe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected bool
	}{
		{tfhe.FheUint4, 2, 1, true},
		{tfhe.FheUint8, 2, 1, true},
		{tfhe.FheUint16, 4283, 1337, true},
		{tfhe.FheUint32, 1333337, 1337, true},
		{tfhe.FheUint64, 13333377777777777, 133377777777, true},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeNe with %s", tc.typ), func(t *testing.T) {
			teeComparison1Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeMinRun(t *testing.T) {
	signature := "teeMin(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1337},
		{tfhe.FheUint32, 1333337, 1337, 1337},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 133377777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMin with %s", tc.typ), func(t *testing.T) {
			teeComparison2Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeMaxRun(t *testing.T) {
	signature := "teeMax(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 2},
		{tfhe.FheUint8, 2, 1, 2},
		{tfhe.FheUint16, 4283, 1337, 4283},
		{tfhe.FheUint32, 1333337, 1337, 1333337},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333377777777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMax with %s", tc.typ), func(t *testing.T) {
			teeComparison2Helper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeSelectRun(t *testing.T) {
	signature := "teeSelect(uint256,uint256,uint256)"

	testcases := []struct {
		typ      tfhe.FheUintType
		fhs      bool
		shs      uint64
		ths      uint64
		expected uint64
	}{
		{tfhe.FheUint4, true, 2, 1, 2},
		{tfhe.FheUint8, true, 2, 1, 2},
		{tfhe.FheUint16, true, 4283, 1337, 4283},
		{tfhe.FheUint32, true, 1333337, 1337, 1333337},
		{tfhe.FheUint64, true, 13333377777777777, 133377777777, 13333377777777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeSelect with %s", tc.typ), func(t *testing.T) {
			teeComparison3Helper(t, tc.typ, tc.fhs, tc.shs, tc.ths, tc.expected, signature)
		})
	}
}

// teeComparisonHelper is a helper function to test TEE comparison operations,
// which are passed into the last argument as a function.
func teeComparison1Helper(t *testing.T, fheUintType tfhe.FheUintType, lhs, rhs uint64, expected bool, signature string) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsCt, err := importTeePlaintextToEVM(environment, depth, lhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}
	rhsCt, err := importTeePlaintextToEVM(environment, depth, rhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	input := toLibPrecompileInput(signature, false, lhsCt.GetHash(), rhsCt.GetHash())
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	teePlaintext, err := tee.Decrypt(res.ciphertext)
	if err != nil {
		t.Fatalf(err.Error())
	}

	var result bool
	if teePlaintext.Value[0] == 1 {
		result = true
	} else {
		result = false
	}

	if result != expected {
		t.Fatalf("incorrect result, expected=%t, got=%t", expected, result)
	}
}

func teeComparison2Helper(t *testing.T, fheUintType tfhe.FheUintType, lhs, rhs, expected uint64, signature string) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsCt, err := importTeePlaintextToEVM(environment, depth, lhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}
	rhsCt, err := importTeePlaintextToEVM(environment, depth, rhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	input := toLibPrecompileInput(signature, false, lhsCt.GetHash(), rhsCt.GetHash())
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	teePlaintext, err := tee.Decrypt(res.ciphertext)
	if err != nil {
		t.Fatalf(err.Error())
	}

	result := new(big.Int).SetBytes(teePlaintext.Value).Uint64()

	if result != expected {
		t.Fatalf("incorrect result, expected=%d, got=%d", expected, result)
	}
}

func teeComparison3Helper(t *testing.T, fheUintType tfhe.FheUintType, fhs bool, shs, ths, expected uint64, signature string) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	fhsCt, err := importTeePlaintextToEVM(environment, depth, fhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}
	shsCt, err := importTeePlaintextToEVM(environment, depth, shs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}
	thsCt, err := importTeePlaintextToEVM(environment, depth, ths, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	input := toLibPrecompileInput(signature, false, fhsCt.GetHash(), shsCt.GetHash(), thsCt.GetHash())
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	teePlaintext, err := tee.Decrypt(res.ciphertext)
	if err != nil {
		t.Fatalf(err.Error())
	}

	result := new(big.Int).SetBytes(teePlaintext.Value).Uint64()

	if result != expected {
		t.Fatalf("incorrect result, expected=%d, got=%d", expected, result)
	}
}

