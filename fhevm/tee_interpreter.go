package fhevm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"go.opentelemetry.io/otel/trace"
)

// doOp is a function to do TEE operations
// We use uint64 because we need to use only types smaller than uint64
func doOp(
	environment EVMEnvironment,
	caller common.Address,
	input []byte,
	runSpan trace.Span,
	operator func(a, b uint64) uint64,
	op string,
) ([]byte, error) {
	logger := environment.GetLogger()

	lp, rp, lhs, rhs, isScalar, err := extract2Operands(op, environment, input, runSpan)
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
		// panic("TODO implement me")
		logger.Error("unsupported FheUintType: %s", lp.FheUintType)
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert the
	// result back to the FheUintType.
	l := big.NewInt(0).SetBytes(lp.Value).Uint64()
	r := big.NewInt(0).SetBytes(rp.Value).Uint64()

	result := operator(l, r)

	var resultBz []byte
	resultBz, err = marshalTfheType(result, lp.FheUintType)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	teePlaintext := tee.NewTeePlaintext(resultBz, lp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	if !isScalar {
		logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	} else {
		logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs, "result", resultHash.Hex())
	}
	return resultHash[:], nil
}

// doEqNeOp is a function to do TEE Eq/Ne operations
// We use big.Int because we need to use FheUint160 for eaddress
func doEqNeOp(
	environment EVMEnvironment,
	caller common.Address,
	input []byte,
	runSpan trace.Span,
	operator func(a, b *big.Int) bool,
	op string,
) ([]byte, error) {
	logger := environment.GetLogger()

	lp, rp, lhs, rhs, isScalar, err := extract2Operands(op, environment, input, runSpan)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if lp.FheUintType == tfhe.FheUint128 {
		// panic("TODO implement me")
		logger.Error("unsupported FheUintType: %s", lp.FheUintType)
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.

	l := big.NewInt(0).SetBytes(lp.Value)
	r := big.NewInt(0).SetBytes(rp.Value)

	result := operator(l, r)

	resultBz, err := marshalTfheType(result, lp.FheUintType)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	teePlaintext := tee.NewTeePlaintext(resultBz, lp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	if !isScalar {
		logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	} else {
		logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs, "result", resultHash.Hex())
	}
	return resultHash[:], nil
}

// doShiftOp is a function to do TEE bit shift operations
// We use uint64 because we need to use only types smaller than uint64
func doShiftOp(
	environment EVMEnvironment,
	caller common.Address,
	input []byte,
	runSpan trace.Span,
	operator func(a, b uint64, typ tfhe.FheUintType) (uint64, error),
	op string,
) ([]byte, error) {
	logger := environment.GetLogger()

	lp, rp, lhs, rhs, isScalar, err := extract2Operands(op, environment, input, runSpan)
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
		// panic("TODO implement me")
		logger.Error("unsupported FheUintType: %s", lp.FheUintType)
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert the
	// result back to the FheUintType.
	l := big.NewInt(0).SetBytes(lp.Value).Uint64()
	r := big.NewInt(0).SetBytes(rp.Value).Uint64()

	result, err := operator(l, r, lp.FheUintType)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	var resultBz []byte
	resultBz, err = marshalTfheType(result, lp.FheUintType)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	teePlaintext := tee.NewTeePlaintext(resultBz, lp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	if !isScalar {
		logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	} else {
		logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs, "result", resultHash.Hex())
	}
	return resultHash[:], nil
}

// doNegNotOp is a generic function to do TEE bit inverse operations
// We use uint64 because we need to use only types smaller than uint64
func doNegNotOp(
	environment EVMEnvironment,
	caller common.Address,
	input []byte,
	runSpan trace.Span,
	operator func(a uint64) uint64,
	op string,
) ([]byte, error) {
	logger := environment.GetLogger()

	cp, ct, err := extract1Operands(op, environment, input, runSpan)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, cp.FheUintType), nil
	}

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if cp.FheUintType == tfhe.FheUint128 || cp.FheUintType == tfhe.FheUint160 {
		// panic("TODO implement me")
		logger.Error("unsupported FheUintType: %s", cp.FheUintType)
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert the
	// result back to the FheUintType.
	c := big.NewInt(0).SetBytes(cp.Value).Uint64()

	result := operator(c)

	var resultBz []byte
	resultBz, err = marshalTfheType(result, cp.FheUintType)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	teePlaintext := tee.NewTeePlaintext(resultBz, cp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", op), "ct", ct.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func extract1Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*tee.TeePlaintext, *verifiedCiphertext, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		msg := "fheNeg input not verified"
		logger.Error(msg, msg, "input", hex.EncodeToString(input))
		return nil, nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	cp, err := tee.Decrypt(ct.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, ct, err
	}

	return &cp, ct, nil
}

func extract2Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*tee.TeePlaintext, *tee.TeePlaintext, *verifiedCiphertext, *verifiedCiphertext, bool, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error(fmt.Sprintf("%s can not detect if operator is meant to be scalar", op), "err", err, "input", hex.EncodeToString(input))
		return nil, nil, nil, nil, false, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error(fmt.Sprintf("%s inputs not verified", op), "err", err, "input", hex.EncodeToString(input))
			return nil, nil, nil, nil, isScalar, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			logger.Error(fmt.Sprintf("%s operand type mismatch", op), "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, nil, lhs, rhs, isScalar, errors.New("operand type mismatch")
		}

		lp, err := tee.Decrypt(lhs.ciphertext)
		if err != nil {
			logger.Error(fmt.Sprintf("%s failed", op), "err", err)
			return nil, nil, lhs, rhs, isScalar, err
		}

		rp, err := tee.Decrypt(rhs.ciphertext)
		if err != nil {
			logger.Error(fmt.Sprintf("%s failed", op), "err", err)
			return nil, nil, lhs, rhs, isScalar, err
		}

		return &lp, &rp, lhs, rhs, isScalar, nil
	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error(fmt.Sprintf("%s inputs not verified", op), "err", err, "input", hex.EncodeToString(input))
			return nil, nil, nil, nil, isScalar, err
		}

		rp := tee.NewTeePlaintext(rhs.Bytes(), tfhe.FheUint128, common.Address{})

		lp, err := tee.Decrypt(lhs.ciphertext)
		if err != nil {
			logger.Error(fmt.Sprintf("%s failed", op), "err", err)
			return nil, nil, lhs, nil, isScalar, err
		}

		return &lp, &rp, lhs, nil, isScalar, nil
	}

}

func extract3Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*tee.TeePlaintext, *tee.TeePlaintext, *tee.TeePlaintext, *verifiedCiphertext, *verifiedCiphertext, *verifiedCiphertext, error) {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()

	fhs, shs, ths, err := get3VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*fhs), encryptedOperand(*shs), encryptedOperand(*ths))
	if err != nil {
		logger.Error(fmt.Sprintf("%s inputs not verified", op), "err", err, "input", hex.EncodeToString(input))
		return nil, nil, nil, nil, nil, nil, err
	}
	if shs.fheUintType() != ths.fheUintType() {
		logger.Error(fmt.Sprintf("%s operand type mismatch", op), "shs", shs.fheUintType(), "ths", ths.fheUintType())
		return nil, nil, nil, nil, nil, nil, errors.New("operand type mismatch")
	}

	fp, err := tee.Decrypt(fhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, nil, fhs, shs, ths, err
	}

	sp, err := tee.Decrypt(shs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, nil, fhs, shs, ths, err
	}

	tp, err := tee.Decrypt(ths.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, nil, fhs, shs, ths, err
	}

	return &fp, &sp, &tp, fhs, shs, ths, nil
}

// marshalTfheType converts a any to a byte slice
func marshalTfheType(value any, typ tfhe.FheUintType) ([]byte, error) {
	switch value := any(value).(type) {
	case uint64:
		switch typ {
		case tfhe.FheBool:
			resultBz := make([]byte, 1)
			resultBz[0] = byte(value)
			return resultBz, nil
		case tfhe.FheUint4:
			resultBz := []byte{byte(value)}
			return resultBz, nil
		case tfhe.FheUint8:
			resultBz := []byte{byte(value)}
			return resultBz, nil
		case tfhe.FheUint16:
			resultBz := make([]byte, 2)
			binary.BigEndian.PutUint16(resultBz, uint16(value))
			return resultBz, nil
		case tfhe.FheUint32:
			resultBz := make([]byte, 4)
			binary.BigEndian.PutUint32(resultBz, uint32(value))
			return resultBz, nil
		case tfhe.FheUint64:
			resultBz := make([]byte, 8)
			binary.BigEndian.PutUint64(resultBz, value)
			return resultBz, nil
		case tfhe.FheUint160:
			resultBz := make([]byte, 8)
			binary.BigEndian.PutUint64(resultBz, value)
			return resultBz, nil
		default:
			return nil,
				fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	case bool:
		resultBz := make([]byte, 1)
		if value {
			resultBz[0] = 1
		} else {
			resultBz[0] = 0
		}
		return resultBz, nil
	case *big.Int:
		resultBz := value.Bytes()
		return resultBz, nil
	default:
		return nil,
			fmt.Errorf("unsupported value type: %s", value)
	}
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1 // true converts to 1
	}
	return 0 // false converts to 0
}
