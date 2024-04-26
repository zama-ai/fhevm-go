package fhevm

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
)

func TestTeeAddRun(t *testing.T) {
	signature := "teeAdd(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 3},
		{tfhe.FheUint8, 2, 1, 3},
		{tfhe.FheUint16, 4283, 1337, 5620},
		{tfhe.FheUint32, 1333337, 1337, 1334674},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333511155555554},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeAdd with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeSubRun(t *testing.T) {
	signature := "teeSub(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 2946},
		{tfhe.FheUint32, 1333337, 1337, 1332000},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333244400000000},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeSub with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeMulRun(t *testing.T) {
	signature := "teeMul(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 3, 6},
		{tfhe.FheUint8, 2, 3, 6},
		{tfhe.FheUint16, 169, 5, 845},
		{tfhe.FheUint32, 137, 17, 2329},
		{tfhe.FheUint64, 137777, 17, 2342209},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMul with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeDivRun(t *testing.T) {
	signature := "teeDiv(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 2},
		{tfhe.FheUint8, 2, 1, 2},
		{tfhe.FheUint16, 4283, 1337, 3},
		{tfhe.FheUint32, 1333337, 1337, 997},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 99967},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeDiv with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeRemRun(t *testing.T) {
	signature := "teeRem(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 272},
		{tfhe.FheUint32, 1333337, 1337, 348},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 1466744418},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeRem with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

// teeArithmeticHelper is a helper function to test TEE arithmetic operations,
// which are passed into the last argument as a function.
func teeArithmeticHelper(t *testing.T, fheUintType tfhe.FheUintType, lhs, rhs, expected uint64, signature string) {
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

	if teePlaintext.FheUintType != fheUintType {
		t.Fatalf("incorrect fheUintType, expected=%s, got=%s", fheUintType, teePlaintext.FheUintType)
	}

	result := new(big.Int).SetBytes(teePlaintext.Value).Uint64()

	if result != expected {
		t.Fatalf("incorrect result, expected=%d, got=%d", expected, result)
	}
}
