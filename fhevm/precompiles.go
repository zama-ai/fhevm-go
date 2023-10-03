package fhevm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/params"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(environment *EVMEnvironment, input []byte) uint64 // RequiredGas calculates the contract gas use
	Run(environment *EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error)
}

var PrecompiledContracts = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{93}): &fheLib{},
}

var signatureFheAdd = makeKeccakSignature("fheAdd(uint256,uint256,bytes1)")

type fheLib struct{}

func (e *fheLib) RequiredGas(environment *EVMEnvironment, input []byte) uint64 {
	logger := (*environment).GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	signature := binary.BigEndian.Uint32(input[0:4])
	switch signature {
	case signatureFheAdd:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheAddRequiredGas(environment, bwCompatBytes)
	default:
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
}

func (e *fheLib) Run(environment *EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := (*environment).GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	signature := binary.BigEndian.Uint32(input[0:4])
	switch signature {
	case signatureFheAdd:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheAddRun(environment, caller, addr, bwCompatBytes, readOnly)
	default:
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
}

var fheAddSubGasCosts = map[fheUintType]uint64{
	FheUint8:  params.FheUint8AddSubGas,
	FheUint16: params.FheUint16AddSubGas,
	FheUint32: params.FheUint32AddSubGas,
}

func fheAddRequiredGas(environment *EVMEnvironment, input []byte) uint64 {
	logger := (*environment).GetLogger()
	isScalar, err := isScalarOp(environment, input)
	if err != nil {
		logger.Error("fheAdd/Sub RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd/Sub RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("fheAdd/Sub RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd/Sub RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}

	return fheAddSubGasCosts[lhs.ciphertext.fheUintType]
}

func fheAddRun(environment *EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := (*environment).GetLogger()

	isScalar, err := isScalarOp(environment, input)
	if err != nil {
		logger.Error("fheAdd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheAdd operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !(*environment).IsCommitting() && !(*environment).IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.add(rhs.ciphertext)
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheAdd success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !(*environment).IsCommitting() && !(*environment).IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarAdd(rhs.Uint64())
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheAdd scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}
