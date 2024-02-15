package fhevm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/crypto"
	"github.com/zama-ai/fhevm-go/kms"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/chacha20"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func fheAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheAdd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheAdd inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheAdd operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Add(rhs.ciphertext)
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheAdd success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheAdd scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarAdd(rhs.Uint64())
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheAdd scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheSub can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheSub inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheSub operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Sub(rhs.ciphertext)
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheSub success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheSub scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarSub(rhs.Uint64())
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheSub scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheMul inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheMul operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Mul(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMul success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheMul scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarMul(rhs.Uint64())
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMul scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheLeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheLe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheLe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheLe operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Le(rhs.ciphertext)
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheLe success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheLe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarLe(rhs.Uint64())
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheLe scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheLtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheLt can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheLt inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheLt operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Lt(rhs.ciphertext)
		if err != nil {
			logger.Error("fheLt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheLt success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheLt scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarLt(rhs.Uint64())
		if err != nil {
			logger.Error("fheLt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheLt scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheEqRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheEq can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheEq inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheEq operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Eq(rhs.ciphertext)
		if err != nil {
			logger.Error("fheEq failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheEq success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheEq scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarEq(rhs.Uint64())
		if err != nil {
			logger.Error("fheEq failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheEq scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheGeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheGe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheGe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheGe operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Ge(rhs.ciphertext)
		if err != nil {
			logger.Error("fheGe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheGe success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheGe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarGe(rhs.Uint64())
		if err != nil {
			logger.Error("fheGe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheGe scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheGtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheGt can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheGt inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheGt operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Gt(rhs.ciphertext)
		if err != nil {
			logger.Error("fheGt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheGt success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheGt scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarGt(rhs.Uint64())
		if err != nil {
			logger.Error("fheGt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheGt scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShl can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheShl inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheShl operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Shl(rhs.ciphertext)
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShl success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheShl scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarShl(rhs.Uint64())
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShl scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheShr inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheShr operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Shr(rhs.ciphertext)
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShr success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheShr scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarShr(rhs.Uint64())
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShr scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheNe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheNe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheNe operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Ne(rhs.ciphertext)
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheNe success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheNe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarNe(rhs.Uint64())
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheNe scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMinRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMin can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheMin inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheMin operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Min(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMin failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMin success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheMin scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarMin(rhs.Uint64())
		if err != nil {
			logger.Error("fheMin failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMin scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMaxRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMax can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheMax inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheMax operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Max(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMax failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMax success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheMax scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarMax(rhs.Uint64())
		if err != nil {
			logger.Error("fheMax failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMax scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()

	if len(input) != 32 {
		msg := "fheMax input needs to contain one 256-bit sized value"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)

	}

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		msg := "fheNeg input not verified"
		logger.Error(msg, msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ct.fheUintType()), nil
	}

	result, err := ct.ciphertext.Neg()
	if err != nil {
		logger.Error("fheNeg failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheNeg success", "ct", ct.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()

	if len(input) != 32 {
		msg := "fheMax input needs to contain one 256-bit sized value"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)

	}

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		msg := "fheNot input not verified"
		logger.Error(msg, msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ct.fheUintType()), nil
	}

	result, err := ct.ciphertext.Not()
	if err != nil {
		logger.Error("fheNot failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheNot success", "ct", ct.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheDiv cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		err = errors.New("fheDiv supports only scalar input operation, two ciphertexts received")
		logger.Error("fheDiv supports only scalar input operation, two ciphertexts received", "input", hex.EncodeToString(input))
		return nil, err
	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheDiv scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarDiv(rhs.Uint64())
		if err != nil {
			logger.Error("fheDiv failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheDiv scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheRem cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		err = errors.New("fheRem supports only scalar input operation, two ciphertexts received")
		logger.Error("fheRem supports only scalar input operation, two ciphertexts received", "input", hex.EncodeToString(input))
		return nil, err
	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheRem scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarRem(rhs.Uint64())
		if err != nil {
			logger.Error("fheRem failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheRem scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheBitAndRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitAnd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitAnd scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheBitAnd inputs not verified", "err", err)
		return nil, err
	}

	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheBitAnd operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	result, err := lhs.ciphertext.Bitand(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitAnd failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheBitAnd success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitOrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitOr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitOr scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheBitOr inputs not verified", "err", err)
		return nil, err
	}

	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheBitOr operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	result, err := lhs.ciphertext.Bitor(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitOr failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheBitOr success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitXorRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitXor can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitXor scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheBitXor inputs not verified", "err", err)
		return nil, err
	}

	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheBitXor operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	result, err := lhs.ciphertext.Bitxor(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitXor failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheBitXor success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

var globalRngSeed []byte

var rngNonceKey [32]byte = uint256.NewInt(0).Bytes32()

func init() {
	if chacha20.NonceSizeX != 24 {
		panic("expected 24 bytes for NonceSizeX")
	}

	// TODO: Since the current implementation is not FHE-based and, hence, not private,
	// we just initialize the global seed with non-random public data. We will change
	// that once the FHE version is available.
	globalRngSeed = make([]byte, chacha20.KeySize)
	for i := range globalRngSeed {
		globalRngSeed[i] = byte(1 + i)
	}
}

// Applies the upperBound (if set) to the rand value and returns the result.
// bitsInRand is the amount of random bits that are contained in rand.
// bitsInRand and upperBound must be powers of 2.
func applyUpperBound(rand uint64, bitsInRand int, upperBound *uint64) uint64 {
	if upperBound == nil {
		return rand
	} else if *upperBound == 0 {
		panic("sliceRandom called with upperBound of 0")
	}
	// Len64() returns the amount of bits needed to represent upperBound. Subtract 1 to get the
	// amount of bits requested by the given upperBound as we want to return a value in the [0, upperBound) range.
	// Note that upperBound is assumed to be a power of 2.
	//
	// For example, if upperBound = 128, then bits = 8 - 1 = 7 random bits to be returned.
	// To get that amount of random bits from rand, subtract bits from bitsInRand, i.e.
	// shift = 32 - 7 = 25. Shifting rand 25 positions would leave 7 of its random bits.
	bits := bits.Len64(*upperBound) - 1
	shift := bitsInRand - bits
	// If the shift ends up negative or 0, just return rand without any shifts.
	if shift <= 0 {
		return rand
	}
	return rand >> shift
}

func generateRandom(environment EVMEnvironment, caller common.Address, resultType FheUintType, upperBound *uint64) ([]byte, error) {
	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() {
		return importRandomCiphertext(environment, resultType), nil
	}

	// Get the RNG nonce.
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(caller)
	currentRngNonceBytes := environment.GetState(protectedStorage, rngNonceKey).Bytes()

	// Increment the RNG nonce by 1.
	nextRngNonce := uint256.NewInt(0).SetBytes(currentRngNonceBytes)
	nextRngNonce = nextRngNonce.AddUint64(nextRngNonce, 1)
	environment.SetState(protectedStorage, rngNonceKey, nextRngNonce.Bytes32())

	// Compute the seed and use it to create a new cipher.
	hasher := crypto.NewKeccakState()
	hasher.Write(globalRngSeed)
	hasher.Write(caller.Bytes())
	seed := common.Hash{}
	_, err := hasher.Read(seed[:])
	if err != nil {
		return nil, err
	}
	// The RNG nonce bytes are of size chacha20.NonceSizeX, which is assumed to be 24 bytes (see init() above).
	// Since uint256.Int.z[0] is the least significant byte and since uint256.Int.Bytes32() serializes
	// in order of z[3], z[2], z[1], z[0], we want to essentially ignore the first byte, i.e. z[3], because
	// it will always be 0 as the nonce size is 24.
	cipher, err := chacha20.NewUnauthenticatedCipher(seed.Bytes(), currentRngNonceBytes[32-chacha20.NonceSizeX:32])
	if err != nil {
		return nil, err
	}

	// XOR a byte array of 0s with the stream from the cipher and receive the result in the same array.
	// Apply upperBound, if set.
	var randUint uint64
	switch resultType {
	case FheUint8:
		randBytes := make([]byte, 1)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(randBytes[0])
		randUint = uint64(applyUpperBound(randUint, 8, upperBound))
	case FheUint16:
		randBytes := make([]byte, 2)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(binary.BigEndian.Uint16(randBytes))
		randUint = uint64(applyUpperBound(randUint, 16, upperBound))
	case FheUint32:
		randBytes := make([]byte, 4)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(binary.BigEndian.Uint32(randBytes))
		randUint = uint64(applyUpperBound(randUint, 32, upperBound))
	case FheUint64:
		randBytes := make([]byte, 8)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(binary.BigEndian.Uint64(randBytes))
		randUint = uint64(applyUpperBound(randUint, 64, upperBound))
	default:
		return nil, fmt.Errorf("generateRandom() invalid type requested: %d", resultType)
	}

	// Trivially encrypt the random integer.
	randCt := new(TfheCiphertext)
	randBigInt := big.NewInt(0)
	randBigInt.SetUint64(randUint)
	randCt.TrivialEncrypt(*randBigInt, resultType)
	importCiphertext(environment, randCt)

	if err != nil {
		return nil, err
	}
	ctHash := randCt.GetHash()
	return ctHash[:], nil
}

func fheRandRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(1, len(input))]

	logger := environment.GetLogger()
	if environment.IsEthCall() {
		msg := "fheRand cannot be called via EthCall, because it needs to mutate internal state"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 1 || !isValidFheType(input[0]) {
		msg := "fheRand input len must be at least 1 byte and be a valid FheUint type"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	resultType := FheUintType(input[0])
	otelDescribeOperandsFheTypes(runSpan, resultType)
	var noUpperBound *uint64 = nil
	return generateRandom(environment, caller, resultType, noUpperBound)
}

func fheRandBoundedRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if environment.IsEthCall() {
		msg := "fheRandBoundedRun cannot be called via EthCall, because it needs to mutate internal state"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	randType, bound, err := parseRandUpperBoundInput(input)
	otelDescribeOperandsFheTypes(runSpan, randType)
	if err != nil {
		msg := "fheRandBounded bound error"
		logger.Error(msg, "input", hex.EncodeToString(input), "err", err)
		return nil, errors.New(msg)
	}
	bound64 := bound.Uint64()
	return generateRandom(environment, caller, randType, &bound64)
}

func fheIfThenElseRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()
	first, second, third, err := get3VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*first), encryptedOperand(*second), encryptedOperand(*third))
	if err != nil {
		logger.Error("fheIfThenElse inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if second.fheUintType() != third.fheUintType() {
		msg := "fheIfThenElse operand type mismatch"
		logger.Error(msg, "second", second.fheUintType(), "third", third.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, second.fheUintType()), nil
	}

	result, err := first.ciphertext.IfThenElse(second.ciphertext, third.ciphertext)
	if err != nil {
		logger.Error("fheIfThenElse failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheIfThenElse success", "first", first.hash().Hex(), "second", second.hash().Hex(), "third", third.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func verifyCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()
	// first 32 bytes of the payload is offset, then 32 bytes are size of byte array
	if len(input) <= 68 {
		err := errors.New("verifyCiphertext(bytes) must contain at least 68 bytes for selector, byte offset and size")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	bytesPaddingSize := 32
	bytesSizeSlotSize := 32
	// read only last 4 bytes of padded number for byte array size
	sizeStart := bytesPaddingSize + bytesSizeSlotSize - 4
	sizeEnd := sizeStart + 4
	bytesSize := binary.BigEndian.Uint32(input[sizeStart:sizeEnd])
	bytesStart := bytesPaddingSize + bytesSizeSlotSize
	bytesEnd := bytesStart + int(bytesSize)
	input = input[bytesStart:minInt(bytesEnd, len(input))]

	if len(input) <= 1 {
		msg := "verifyCiphertext Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ctBytes := input[:len(input)-1]
	ctTypeByte := input[len(input)-1]
	if !isValidFheType(ctTypeByte) {
		msg := "verifyCiphertext Run() ciphertext type is invalid"
		logger.Error(msg, "type", ctTypeByte)
		return nil, errors.New(msg)
	}
	ctType := FheUintType(ctTypeByte)
	otelDescribeOperandsFheTypes(runSpan, ctType)

	expectedSize, found := GetCompactFheCiphertextSize(ctType)
	if !found || expectedSize != uint(len(ctBytes)) {
		msg := "verifyCiphertext Run() compact ciphertext size is invalid"
		logger.Error(msg, "type", ctTypeByte, "size", len(ctBytes), "expectedSize", expectedSize)
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ctType), nil
	}

	ct := new(TfheCiphertext)
	err := ct.DeserializeCompact(ctBytes, ctType)
	if err != nil {
		logger.Error("verifyCiphertext failed to deserialize input ciphertext",
			"err", err,
			"len", len(ctBytes),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
		return nil, err
	}
	ctHash := ct.GetHash()
	importCiphertext(environment, ct)
	if environment.IsCommitting() {
		logger.Info("verifyCiphertext success",
			"ctHash", ctHash.Hex(),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
	}
	return ctHash.Bytes(), nil
}

func reencryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(64, len(input))]
	// precompileBytes, err := reencryptRun(environment, caller, addr, bwCompatBytes, readOnly)

	logger := environment.GetLogger()
	if !environment.IsEthCall() {
		msg := "reencrypt only supported on EthCall"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 64 {
		msg := "reencrypt input len must be 64 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct != nil {
		otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())
		// Make sure we don't decrypt before any optimistic requires are checked.
		// optReqResult, optReqErr := evaluateRemainingOptimisticRequires(environment)
		// if optReqErr != nil {
		// 	return nil, optReqErr
		// } else if !optReqResult {
		// 	return nil, ErrExecutionReverted
		// }

		var fheType kms.FheType
		switch ct.fheUintType() {
		case FheUint8:
			fheType = kms.FheType_Euint8
		case FheUint16:
			fheType = kms.FheType_Euint16
		case FheUint32:
			fheType = kms.FheType_Euint32
		case FheUint64:
			fheType = kms.FheType_Euint64
		}

		pubKey := input[32:64]

		// TODO: generate merkle proof for some data
		proof := &kms.Proof{
			Height:              3,
			MerklePatriciaProof: []byte{},
		}

		reencryptionRequest := &kms.ReencryptionRequest{
			FheType:    fheType,
			Ciphertext: ct.serialization(),
			Request:    pubKey, // TODO: change according to the structure of `Request`
			Proof:      proof,
		}

		conn, err := grpc.Dial(kms.KmsEndpointAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, errors.New("kms unreachable")
		}
		defer conn.Close()

		ep := kms.NewKmsEndpointClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		res, err := ep.Reencrypt(ctx, reencryptionRequest)
		if err != nil {
			return nil, err
		}

		// TODO: decide if `res.Signature` should be verified here

		var reencryptedValue = res.ReencryptedCiphertext

		logger.Info("reencrypt success", "input", hex.EncodeToString(input), "callerAddr", caller, "reencryptedValue", reencryptedValue, "len", len(reencryptedValue))
		reencryptedValue = toEVMBytes(reencryptedValue)
		// pad according to abi specification, first add offset to the dynamic bytes argument
		outputBytes := make([]byte, 32, len(reencryptedValue)+32)
		outputBytes[31] = 0x20
		outputBytes = append(outputBytes, reencryptedValue...)
		return padArrayTo32Multiple(outputBytes), nil
	}
	msg := "reencrypt unverified ciphertext handle"
	logger.Error(msg, "input", hex.EncodeToString(input))
	return nil, errors.New(msg)
}

func optimisticRequireRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		msg := "optimisticRequire input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		msg := "optimisticRequire unverified handle"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())
	// If we are doing gas estimation, don't do anything as we would assume all requires are true.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return nil, nil
	}
	if ct.fheUintType() != FheUint8 {
		msg := "optimisticRequire ciphertext type is not FheUint8"
		logger.Error(msg, "type", ct.fheUintType())
		return nil, errors.New(msg)
	}
	environment.FhevmData().appendOptimisticRequires(ct.ciphertext)
	return nil, nil
}

func decryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
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
	// Make sure we don't decrypt before any optimistic requires are checked.
	optReqResult, optReqErr := evaluateRemainingOptimisticRequires(environment)
	if optReqErr != nil {
		return nil, optReqErr
	} else if !optReqResult {
		return nil, ErrExecutionReverted
	}

	plaintext, err := decryptValue(environment, ct.ciphertext)
	if err != nil {
		logger.Error("decrypt failed", "err", err)
		return nil, err
	}

	logger.Info("decrypt success", "plaintext", plaintext)

	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	bigIntValue := big.NewInt(0)
	bigIntValue.SetUint64(plaintext)
	bigIntValue.FillBytes(ret)
	return ret, nil
}

func decryptValue(environment EVMEnvironment, ct *TfheCiphertext) (uint64, error) {

	logger := environment.GetLogger()
	var fheType kms.FheType
	switch ct.Type() {
	case FheUint8:
		fheType = kms.FheType_Euint8
	case FheUint16:
		fheType = kms.FheType_Euint16
	case FheUint32:
		fheType = kms.FheType_Euint32
	case FheUint64:
		fheType = kms.FheType_Euint64
	}

	// TODO: generate merkle proof for some data
	proof := &kms.Proof{
		Height:              4,
		MerklePatriciaProof: []byte{},
	}

	decryptionRequest := &kms.DecryptionRequest{
		FheType:    fheType,
		Ciphertext: ct.Serialize(),
		Request:    []byte{}, // TODO: change according to the structure of `Request`
		Proof:      proof,
	}

	conn, err := grpc.Dial(kms.KmsEndpointAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return 0, errors.New("kms unreachable")
	}
	defer conn.Close()

	ep := kms.NewKmsEndpointClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res, err := ep.Decrypt(ctx, decryptionRequest)
	if err != nil {
		logger.Error("decrypt failed", "err", err)
		return 0, err
	}

	return uint64(res.Plaintext), err
}

// If there are optimistic requires, check them by doing bitwise AND on all of them.
// That works, because we assume their values are either 0 or 1. If there is at least
// one 0, the result will be 0 (false).
func evaluateRemainingOptimisticRequires(environment EVMEnvironment) (bool, error) {
	requires := environment.FhevmData().optimisticRequires
	len := len(requires)
	defer func() { environment.FhevmData().resetOptimisticRequires() }()
	if len != 0 {
		var cumulative *TfheCiphertext = requires[0]
		var err error
		for i := 1; i < len; i++ {
			cumulative, err = cumulative.Bitand(requires[i])
			if err != nil {
				environment.GetLogger().Error("evaluateRemainingOptimisticRequires bitand failed", "err", err)
				return false, err
			}
		}
		result, err := decryptValue(environment, cumulative)
		return result != 0, err
	}
	return true, nil
}

func castRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
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

	if !isValidFheType(input[32]) {
		logger.Error("invalid type to cast to")
		return nil, errors.New("invalid type provided")
	}
	castToType := FheUintType(input[32])

	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType(), castToType)

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, castToType), nil
	}

	res, err := ct.ciphertext.CastTo(castToType)
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

var fhePubKeyHashPrecompile = common.BytesToAddress([]byte{93})
var fhePubKeyHashSlot = common.Hash{}

func fhePubKeyRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(1, len(input))]

	existing := environment.GetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot)
	if existing != GetPksHash() {
		msg := "fhePubKey FHE public key hash doesn't match one stored in state"
		environment.GetLogger().Error(msg, "existing", existing.Hex(), "pksHash", GetPksHash().Hex())
		return nil, errors.New(msg)
	}
	// serialize public key
	pksBytes, err := serializePublicKey()
	if err != nil {
		return nil, err
	}
	// If we have a single byte with the value of 1, make as an EVM array.
	if len(input) == 1 && input[0] == 1 {
		pksBytes = toEVMBytes(pksBytes)
	}
	// pad according to abi specification, first add offset to the dynamic bytes argument
	outputBytes := make([]byte, 32, len(pksBytes)+32)
	outputBytes[31] = 0x20
	outputBytes = append(outputBytes, pksBytes...)
	return padArrayTo32Multiple(outputBytes), nil
}

func trivialEncryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "trivialEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := FheUintType(input[32])
	otelDescribeOperandsFheTypes(runSpan, encryptToType)

	ct := new(TfheCiphertext).TrivialEncrypt(valueToEncrypt, encryptToType)

	ctHash := ct.GetHash()
	importCiphertext(environment, ct)
	if environment.IsCommitting() {
		logger.Info("trivialEncrypt success",
			"ctHash", ctHash.Hex(),
			"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}
