package fhevm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"pgregory.net/rapid"
)

func TestTeeDecryptRun(t *testing.T) {
	signature := "teeDecrypt(uint256)"
	rapid.Check(t, func(t *rapid.T) {
		testcases := []struct {
			typ      tfhe.FheUintType
			expected uint64
		}{
			{tfhe.FheUint4, uint64(rapid.Uint8Range(0, 15).Draw(t, "expected"))},
			{tfhe.FheUint8, uint64(rapid.Uint8().Draw(t, "expected"))},
			{tfhe.FheUint16, uint64(rapid.Uint16().Draw(t, "expected"))},
			{tfhe.FheUint32, uint64(rapid.Uint32().Draw(t, "expected"))},
			{tfhe.FheUint64, rapid.Uint64().Draw(t, "expected")},
		}
		for _, tc := range testcases {
			depth := 1
			environment := newTestEVMEnvironment()
			environment.depth = depth
			addr := common.Address{}
			readOnly := false
			ct, err := importTeePlaintextToEVM(environment, depth, tc.expected, tc.typ)
			if err != nil {
				t.Fatalf(err.Error())
			}

			input := toLibPrecompileInput(signature, false, ct.GetHash())
			out, err := FheLibRun(environment, addr, addr, input, readOnly)
			if err != nil {
				t.Fatalf(err.Error())
			}

			result := new(big.Int).SetBytes(out).Uint64()
			if result != tc.expected {
				t.Fatalf("incorrect result, expected=%d, got=%d", tc.expected, result)
			}
		}
	})
}

func TestTeeVerifyCiphertext4(t *testing.T) {
	TeeVerifyCiphertext(t, tfhe.FheUint4)
}

func TestTeeVerifyCiphertext8(t *testing.T) {
	TeeVerifyCiphertext(t, tfhe.FheUint8)
}

func TestTeeVerifyCiphertext16(t *testing.T) {
	TeeVerifyCiphertext(t, tfhe.FheUint16)
}

func TestTeeVerifyCiphertext32(t *testing.T) {
	TeeVerifyCiphertext(t, tfhe.FheUint32)
}

func TestTeeVerifyCiphertext64(t *testing.T) {
	TeeVerifyCiphertext(t, tfhe.FheUint64)
}

func TestTeeVerifyCiphertext4BadType(t *testing.T) {
	TeeVerifyCiphertextBadType(t, tfhe.FheUint4, tfhe.FheUint8)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint4, tfhe.FheUint16)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint4, tfhe.FheUint32)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint4, tfhe.FheUint64)
}

func TestTeeVerifyCiphertext8BadType(t *testing.T) {
	TeeVerifyCiphertextBadType(t, tfhe.FheUint8, tfhe.FheUint4)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint8, tfhe.FheUint16)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint8, tfhe.FheUint32)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint8, tfhe.FheUint64)
}

func TestTeeVerifyCiphertext16BadType(t *testing.T) {
	TeeVerifyCiphertextBadType(t, tfhe.FheUint16, tfhe.FheUint4)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint16, tfhe.FheUint8)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint16, tfhe.FheUint32)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint16, tfhe.FheUint64)
}

func TestTeeVerifyCiphertext32BadType(t *testing.T) {
	TeeVerifyCiphertextBadType(t, tfhe.FheUint32, tfhe.FheUint4)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint32, tfhe.FheUint8)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint32, tfhe.FheUint16)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint32, tfhe.FheUint64)
}

func TestTeeVerifyCiphertext64BadType(t *testing.T) {
	TeeVerifyCiphertextBadType(t, tfhe.FheUint64, tfhe.FheUint4)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint64, tfhe.FheUint8)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint64, tfhe.FheUint16)
	TeeVerifyCiphertextBadType(t, tfhe.FheUint64, tfhe.FheUint32)
}

func TeeVerifyCiphertext(t *testing.T, fheUintType tfhe.FheUintType) {
	var value uint64
	switch fheUintType {
	case tfhe.FheBool:
		value = 1
	case tfhe.FheUint4:
		value = 2
	case tfhe.FheUint8:
		value = 234
	case tfhe.FheUint16:
		value = 4283
	case tfhe.FheUint32:
		value = 1333337
	case tfhe.FheUint64:
		value = 13333377777777777
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false

	resultBz, err := tee.MarshalTfheType(value, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	plaintext := tee.NewTeePlaintext(resultBz, fheUintType, addr)
	ct, err := tee.Encrypt(plaintext)
	if err != nil {
		t.Fatalf(err.Error())
	}

	input := prepareInputForVerifyCiphertext(append(ct.Serialization, byte(fheUintType)))
	out, err := teeVerifyCiphertextRun(environment, addr, addr, input, readOnly, nil)
	if err != nil {
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

func TeeVerifyCiphertextBadType(t *testing.T, actualType tfhe.FheUintType, metadataType tfhe.FheUintType) {
	var value uint64
	switch actualType {
	case tfhe.FheUint4:
		value = 2
	case tfhe.FheUint8:
		value = 2
	case tfhe.FheUint16:
		value = 4283
	case tfhe.FheUint32:
		value = 1333337
	case tfhe.FheUint64:
		value = 13333377777777777
	}
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false

	resultBz, err := tee.MarshalTfheType(value, actualType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	plaintext := tee.NewTeePlaintext(resultBz, actualType, addr)
	ct, err := tee.Encrypt(plaintext)
	if err != nil {
		t.Fatalf(err.Error())
	}

	input := prepareInputForVerifyCiphertext(append(ct.Serialization, byte(metadataType)))
	_, err = teeVerifyCiphertextRun(environment, addr, addr, input, readOnly, nil)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on type mismatch")
	}

	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("verifyCiphertext mustn't have verified given ciphertext")
	}
}
