package fhevm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
)

// teeOperationHelper is a helper function to test TEE operations,
// which are passed into the last argument as a function.
func teeOperationHelper(t *testing.T, fheUintType tfhe.FheUintType, lhs, rhs, expected any, signature string, isScalar bool) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsCt, err := importTeePlaintextToEVM(environment, depth, lhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	var input []byte
	if !isScalar {
		rhsCt, err := importTeePlaintextToEVM(environment, depth, rhs, fheUintType)
		if err != nil {
			t.Fatalf(err.Error())
		}
		input = toLibPrecompileInput(signature, false, lhsCt.GetHash(), rhsCt.GetHash())
	} else {
		valueBz, _ := marshalTfheType(rhs, fheUintType)
		input = toLibPrecompileInput(signature, true, lhsCt.GetHash(), common.BytesToHash(valueBz))
	}

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

	var expect uint64
	switch expected := expected.(type) {
	case bool:
		expect = boolToUint64(expected)
	case uint64:
		expect = expected
	default:
		expect = 0
	}
	if result != expect {
		t.Fatalf("incorrect result, expected=%d, got=%d", expected, result)
	}
}

// teeSelectHelper is a helper function to test teeSelect operation,
// which are passed into the last argument as a function.
func teeSelectOperationHelper(t *testing.T, fheUintType tfhe.FheUintType, fhs bool, shs, ths, expected *big.Int, signature string) {
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

	result := new(big.Int).SetBytes(teePlaintext.Value)

	if result.Cmp(expected) != 0 {
		t.Fatalf("incorrect result, expected=%d, got=%d", expected, result)
	}
}

// teeNotNegHelper is a helper function to test TEE operations,
// which are passed into the last argument as a function.
func teeNegNotOperationHelper(t *testing.T, fheUintType tfhe.FheUintType, chs, expected uint64, signature string) {
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	chsCt, err := importTeePlaintextToEVM(environment, depth, chs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	input := toLibPrecompileInput(signature, false, chsCt.GetHash())
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

func importTeePlaintextToEVM(environment EVMEnvironment, depth int, value any, typ tfhe.FheUintType) (tfhe.TfheCiphertext, error) {
	valueBz, err := marshalTfheType(value, typ)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	teePlaintext := tee.NewTeePlaintext(valueBz, typ, common.Address{})

	ct, err := tee.Encrypt(teePlaintext)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}

	importCiphertextToEVMAtDepth(environment, &ct, depth)
	return ct, nil
}
