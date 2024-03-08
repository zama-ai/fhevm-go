package fhevm

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func verifyCiphertextRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	if len(input) <= 1 {
		environment.GetLogger().Error(
			"verifyCiphertext RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	ctType := tfhe.FheUintType(input[len(input)-1])
	return environment.FhevmParams().GasCosts.FheVerify[ctType]
}

func reencryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(64, len(input))]

	logger := environment.GetLogger()
	if len(input) != 64 {
		logger.Error("reencrypt RequiredGas() input len must be 64 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("reencrypt RequiredGas() input doesn't point to verified ciphertext", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheReencrypt[ct.fheUintType()]
}

func getCiphertextRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(64, len(input))]

	logger := environment.GetLogger()
	if len(input) != 64 {
		logger.Error("getCiphertext RequiredGas() input len must be 64 bytes",
			"input", hex.EncodeToString(input), "len", len(input))
		return 0
	}

	contractAddress := common.BytesToAddress(input[:32])
	handle := common.BytesToHash(input[32:])
	metadata := getCiphertextMetadataFromProtectedStorage(environment, contractAddress, handle)
	if metadata == nil {
		return GetNonExistentCiphertextGas
	}
	return environment.FhevmParams().GasCosts.FheGetCiphertext[metadata.fheUintType]
}

func castRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	if len(input) != 33 {
		environment.GetLogger().Error(
			"cast RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheCast
}

func decryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("decrypt RequiredGas() input len must be 32 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		logger.Error("decrypt RequiredGas() input doesn't point to verified ciphertext", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheDecrypt[ct.fheUintType()]
}

func fhePubKeyRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return environment.FhevmParams().GasCosts.FhePubKey
}

func trivialEncryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		logger.Error("trivialEncrypt RequiredGas() input len must be 33 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	encryptToType := tfhe.FheUintType(input[32])
	return environment.FhevmParams().GasCosts.FheTrivialEncrypt[encryptToType]
}
