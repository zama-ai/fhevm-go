package fhevm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/sgx"
	"go.opentelemetry.io/otel/trace"
)

func extract2Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*sgx.SgxPlaintext, *sgx.SgxPlaintext, *verifiedCiphertext, *verifiedCiphertext, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error(fmt.Sprintf("%s inputs not verified", op), "err", err, "input", hex.EncodeToString(input))
		return nil, nil, nil, nil, err
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error(fmt.Sprintf("%s operand type mismatch", op), "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, nil, nil, nil, errors.New("operand type mismatch")
	}

	lp, err := sgx.Decrypt(lhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	rp, err := sgx.Decrypt(rhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	return &lp, &rp, lhs, rhs, nil
}

func doArithmeticOperation(op string, environment EVMEnvironment, caller common.Address, input []byte, runSpan trace.Span, operator func(uint64, uint64) uint64) ([]byte, error) {
	logger := environment.GetLogger()

	lp, rp, lhs, rhs, err := extract2Operands(op, environment, input, runSpan)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if lp.FheUintType == tfhe.FheUint128 || lp.FheUintType == tfhe.FheUint160 {
		panic("TODO implement me")
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert th
	// result back to the FheUintType.
	l := big.NewInt(0).SetBytes(lp.Value).Uint64()
	r := big.NewInt(0).SetBytes(rp.Value).Uint64()

	result := operator(l, r)
	resultBz, err := marshalUint(result, lhs.fheUintType())
	if err != nil {
		return nil, err
	}
	sgxPlaintext := sgx.NewSgxPlaintext(resultBz, lhs.fheUintType(), caller)

	resultCt, err := sgx.Encrypt(sgxPlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func sgxAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("sgxAddRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a + b
	})
}

func sgxSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("sgxSubRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a - b
	})
}

func sgxMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("sgxMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a * b
	})
}

// marshalUint converts a uint64 to a byte slice whose length is based on the
// FheUintType.
func marshalUint(value uint64, typ tfhe.FheUintType) ([]byte, error) {
	var resultBz []byte

	switch typ {
	case tfhe.FheUint4:
		resultBz = []byte{byte(value)}
	case tfhe.FheUint8:
		resultBz = []byte{byte(value)}
	case tfhe.FheUint16:
		resultBz = make([]byte, 2)
		binary.BigEndian.PutUint16(resultBz, uint16(value))
	case tfhe.FheUint32:
		resultBz = make([]byte, 4)
		binary.BigEndian.PutUint32(resultBz, uint32(value))
	case tfhe.FheUint64:
		resultBz = make([]byte, 8)
		binary.BigEndian.PutUint64(resultBz, value)
	default:
		return nil, fmt.Errorf("unsupported FheUintType: %s", typ)
	}

	return resultBz, nil
}
