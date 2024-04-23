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
	op := func(lhs, rhs uint64) uint64 {
		return lhs + rhs
	}
	signature := "teeAdd(uint256,uint256,bytes1)"

	testcases := []struct {
		typ tfhe.FheUintType
		lhs uint64
		rhs uint64
	}{
		{tfhe.FheUint4, 2, 1},
		{tfhe.FheUint8, 2, 1},
		{tfhe.FheUint16, 4283, 1337},
		{tfhe.FheUint32, 1333337, 1337},
		{tfhe.FheUint64, 13333377777777777, 133377777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeAdd with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, op, signature)
		})
	}
}

func TestTeeSubRun(t *testing.T) {
	op := func(lhs, rhs uint64) uint64 {
		return lhs - rhs
	}
	signature := "teeSub(uint256,uint256,bytes1)"

	testcases := []struct {
		typ tfhe.FheUintType
		lhs uint64
		rhs uint64
	}{
		{tfhe.FheUint4, 2, 1},
		{tfhe.FheUint8, 2, 1},
		{tfhe.FheUint16, 4283, 1337},
		{tfhe.FheUint32, 1333337, 1337},
		{tfhe.FheUint64, 13333377777777777, 133377777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeSub with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, op, signature)
		})
	}
}

func TestTeeMulRun(t *testing.T) {
	op := func(lhs, rhs uint64) uint64 {
		return lhs * rhs
	}
	signature := "teeMul(uint256,uint256,bytes1)"

	testcases := []struct {
		typ tfhe.FheUintType
		lhs uint64
		rhs uint64
	}{
		{tfhe.FheUint4, 2, 3},
		{tfhe.FheUint8, 2, 3},
		{tfhe.FheUint16, 169, 5},
		{tfhe.FheUint32, 137, 17},
		{tfhe.FheUint64, 137777, 17},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMul with %s", tc.typ), func(t *testing.T) {
			teeArithmeticHelper(t, tc.typ, tc.lhs, tc.rhs, op, signature)
		})
	}
}

// teeArithmeticHelper is a helper function to test TEE arithmetic operations,
// which are passed into the last argument as a function.
func teeArithmeticHelper(t *testing.T, fheUintType tfhe.FheUintType, lhs, rhs uint64, op func(lhs, rhs uint64) uint64, signature string) {
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

	expected := op(lhs, rhs)
	if result != expected {
		t.Fatalf("incorrect result, expected=%d, got=%d", expected, result)
	}
}

func importTeePlaintextToEVM(environment EVMEnvironment, depth int, value uint64, typ tfhe.FheUintType) (tfhe.TfheCiphertext, error) {
	valueBz, err := marshalUint(value, typ)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	teePlaintext := tee.NewTeePlaintext(valueBz, typ, common.Address{})

	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	ct, err := tee.Encrypt(teePlaintext)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}

	importCiphertextToEVMAtDepth(environment, &ct, depth)
	return ct, nil
}
