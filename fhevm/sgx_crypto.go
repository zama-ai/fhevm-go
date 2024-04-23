package fhevm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/sgx"
	"go.opentelemetry.io/otel/trace"
)

func sgxEncryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "sgxEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := tfhe.FheUintType(input[32])
	otelDescribeOperandsFheTypes(runSpan, encryptToType)

	sgxPlaintext := sgx.NewSgxPlaintext(input[0:32], encryptToType, caller)

	ct, err := sgx.Encrypt(sgxPlaintext)

	if err != nil {
		logger.Error("sgxEncrypt failed", "err", err)
		return nil, err
	}

	ctHash := ct.GetHash()
	importCiphertext(environment, &ct)
	if environment.IsCommitting() {
		logger.Info("sgxEncrypt success",
			"ctHash", ctHash.Hex(),
			"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}

func sgxDecryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

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
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	// If we are doing gas estimation, skip decryption and make sure we return the maximum possible value.
	// We need that, because non-zero bytes cost more than zero bytes in some contexts (e.g. SSTORE or memory operations).
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return bytes.Repeat([]byte{0xFF}, 32), nil
	}

	result, err := sgx.Decrypt(ct.ciphertext)
	if err != nil {
		logger.Error("sgxDecrypt failed", "err", err)
		return nil, err
	}
	plaintext := result.Value

	logger.Info("sgxDecrypt success", "plaintext", plaintext)

	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	copy(ret[32-len(plaintext):], plaintext)
	return ret, nil
}
