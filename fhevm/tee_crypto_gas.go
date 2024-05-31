package fhevm

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func teeEncryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		logger.Error("teeEncrypt RequiredGas() input len must be 33 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	encryptToType := tfhe.FheUintType(input[32])
	return environment.FhevmParams().GasCosts.FheTrivialEncrypt[encryptToType]
}

func teeDecryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("teeDecrypt RequiredGas() input len must be 32 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		logger.Error("teeDecrypt RequiredGas() input doesn't point to verified ciphertext", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.TeeDecrypt[ct.fheUintType()]
}

func teeVerifyCiphertextRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()

	if len(input) <= 68 {
		logger.Error("verifyCiphertext(bytes) must contain at least 68 bytes for selector, byte offset and size")
		return 0
	}
	ctTypeByte := input[len(input)-1]
	if !tfhe.IsValidFheType(ctTypeByte) {
		msg := "verifyCiphertext Run() ciphertext type is invalid"
		logger.Error(msg, "type", ctTypeByte)
		return 0
	}

	ctType := tfhe.FheUintType(ctTypeByte)
	return environment.FhevmParams().GasCosts.TeeVerifyCiphertext[ctType]
}
