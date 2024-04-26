package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
)

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
