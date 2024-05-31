package fhevm

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"go.opentelemetry.io/otel/trace"
)

func teeCastTo(ciphertext *tfhe.TfheCiphertext, castToType tfhe.FheUintType) (*tfhe.TfheCiphertext, error) {
	if ciphertext.FheUintType == castToType {
		return nil, errors.New("casting to same type is not supported")
	}

	result, err := tee.Decrypt(ciphertext)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	value := big.NewInt(0).SetBytes(result.Value).Uint64()

	resultBz, err := tee.MarshalTfheType(value, castToType)
	if err != nil {
		return nil, errors.New("marshalling failed")
	}

	teePlaintext := tee.NewTeePlaintext(resultBz, castToType, common.Address{})

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		return nil, errors.New("encryption failed")
	}

	return &resultCt, nil
}

func teeCastRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "cast Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("cast input not verified")
		return nil, errors.New("unverified ciphertext handle")
	}

	if !tfhe.IsValidFheType(input[32]) {
		logger.Error("invalid type to cast to")
		return nil, errors.New("invalid type provided")
	}
	castToType := tfhe.FheUintType(input[32])

	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType(), castToType)

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, castToType), nil
	}

	res, err := teeCastTo(ct.ciphertext, castToType)

	if err != nil {
		msg := "cast Run() error casting ciphertext to"
		logger.Error(msg, "type", castToType)
		return nil, errors.New(msg)
	}

	resHash := res.GetHash()

	importCiphertext(environment, res)
	if environment.IsCommitting() {
		logger.Info("cast success",
			"ctHash", resHash.Hex(),
		)
	}

	return resHash.Bytes(), nil
}
