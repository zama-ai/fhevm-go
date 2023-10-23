package fhevm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

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

var ErrExecutionReverted = errors.New("execution reverted")

var signatureFheAdd = makeKeccakSignature("fheAdd(uint256,uint256,bytes1)")
var signatureFheSub = makeKeccakSignature("fheSub(uint256,uint256,bytes1)")
var signatureFheMul = makeKeccakSignature("fheMul(uint256,uint256,bytes1)")
var signatureFheLe = makeKeccakSignature("fheLe(uint256,uint256,bytes1)")
var signatureFheNe = makeKeccakSignature("fheNe(uint256,uint256,bytes1)")
var signatureCast = makeKeccakSignature("cast(uint256,bytes1)")
var signatureDecrypt = makeKeccakSignature("decrypt(uint256)")
var signatureFhePubKey = makeKeccakSignature("fhePubKey(bytes1)")
var signatureTrivialEncrypt = makeKeccakSignature("trivialEncrypt(uint256,bytes1)")
var signatureVerifyCiphertext = makeKeccakSignature("verifyCiphertext(bytes)")

func FheLibRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
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
	case signatureFheSub:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheSubRequiredGas(environment, bwCompatBytes)
	case signatureFheMul:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMulRequiredGas(environment, bwCompatBytes)
	case signatureFheLe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheLeRequiredGas(environment, bwCompatBytes)
	case signatureFheNe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheNeRequiredGas(environment, bwCompatBytes)
	case signatureCast:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return castRequiredGas(environment, bwCompatBytes)
	case signatureDecrypt:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return decryptRequiredGas(environment, bwCompatBytes)
	case signatureFhePubKey:
		bwCompatBytes := input[4:minInt(5, len(input))]
		return fhePubKeyRequiredGas(environment, bwCompatBytes)
	case signatureTrivialEncrypt:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return trivialEncryptRequiredGas(environment, bwCompatBytes)
	case signatureVerifyCiphertext:
		bwCompatBytes := input[4:]
		return verifyCiphertextRequiredGas(environment, bwCompatBytes)
	default:
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
}

func FheLibRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
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
	case signatureFheSub:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheSubRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheMul:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMulRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheLe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheLeRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheNe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheNeRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureCast:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return castRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureDecrypt:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return decryptRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFhePubKey:
		bwCompatBytes := input[4:minInt(5, len(input))]
		precompileBytes, err := fhePubKeyRun(environment, caller, addr, bwCompatBytes, readOnly)
		if err != nil {
			return precompileBytes, err
		}
		// pad according to abi specification, first add offset to the dynamic bytes argument
		outputBytes := make([]byte, 32, len(precompileBytes)+32)
		outputBytes[31] = 0x20
		outputBytes = append(outputBytes, precompileBytes...)
		return padArrayTo32Multiple(outputBytes), nil
	case signatureTrivialEncrypt:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return trivialEncryptRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureVerifyCiphertext:
		// first 32 bytes of the payload is offset, then 32 bytes are size of byte array
		if len(input) <= 68 {
			err := errors.New("verifyCiphertext(bytes) must contain at least 68 bytes for selector, byte offset and size")
			logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		bytesPaddingSize := 32
		bytesSizeSlotSize := 32
		// read only last 4 bytes of padded number for byte array size
		sizeStart := 4 + bytesPaddingSize + bytesSizeSlotSize - 4
		sizeEnd := sizeStart + 4
		bytesSize := binary.BigEndian.Uint32(input[sizeStart:sizeEnd])
		bytesStart := 4 + bytesPaddingSize + bytesSizeSlotSize
		bytesEnd := bytesStart + int(bytesSize)
		bwCompatBytes := input[bytesStart:minInt(bytesEnd, len(input))]
		return verifyCiphertextRun(environment, caller, addr, bwCompatBytes, readOnly)
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

var fheDecryptGasCosts = map[fheUintType]uint64{
	FheUint8:  params.FheUint8DecryptGas,
	FheUint16: params.FheUint16DecryptGas,
	FheUint32: params.FheUint32DecryptGas,
}

// Gas costs
func fheAddRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
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

func fheSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of add, because add and sub costs are currently the same.
	return fheAddRequiredGas(environment, input)
}

var fheMulGasCosts = map[fheUintType]uint64{
	FheUint8:  params.FheUint8MulGas,
	FheUint16: params.FheUint16MulGas,
	FheUint32: params.FheUint32MulGas,
}

func fheMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheMul RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("fheMul RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMul RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return fheMulGasCosts[lhs.ciphertext.fheUintType]
}

func fheNeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

var fheLeGasCosts = map[fheUintType]uint64{
	FheUint8:  params.FheUint8LeGas,
	FheUint16: params.FheUint16LeGas,
	FheUint32: params.FheUint32LeGas,
}

func fheLeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("comparison RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("comparison RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return fheLeGasCosts[lhs.ciphertext.fheUintType]
}

func castRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	if len(input) != 33 {
		environment.GetLogger().Error(
			"cast RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	return params.FheCastGas
}

func decryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
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
	return fheDecryptGasCosts[ct.ciphertext.fheUintType]
}

func fhePubKeyRequiredGas(accessibleState EVMEnvironment, input []byte) uint64 {
	return params.FhePubKeyGas
}

var fheTrivialEncryptGasCosts = map[fheUintType]uint64{
	FheUint8:  params.FheUint8TrivialEncryptGas,
	FheUint16: params.FheUint16TrivialEncryptGas,
	FheUint32: params.FheUint32TrivialEncryptGas,
}

func trivialEncryptRequiredGas(accessibleState EVMEnvironment, input []byte) uint64 {
	logger := accessibleState.GetLogger()
	if len(input) != 33 {
		logger.Error("trivialEncrypt RequiredGas() input len must be 33 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	encryptToType := fheUintType(input[32])
	return fheTrivialEncryptGasCosts[encryptToType]
}

var fheVerifyGasCosts = map[fheUintType]uint64{
	FheUint8:  params.FheUint8VerifyGas,
	FheUint16: params.FheUint16VerifyGas,
	FheUint32: params.FheUint32VerifyGas,
}

func verifyCiphertextRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	if len(input) <= 1 {
		environment.GetLogger().Error(
			"verifyCiphertext RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	ctType := fheUintType(input[len(input)-1])
	return fheVerifyGasCosts[ctType]
}

// Implementations
func fheAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
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
		if !environment.IsCommitting() && !environment.IsEthCall() {
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
		if !environment.IsCommitting() && !environment.IsEthCall() {
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

func fheSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheSub can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheSub inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheSub operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.sub(rhs.ciphertext)
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheSub success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheSub scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarSub(rhs.Uint64())
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheSub scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheMul inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheMul operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.mul(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMul success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMul scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarMul(rhs.Uint64())
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMul scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheLeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheLe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheLe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheLe operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.le(rhs.ciphertext)
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheLe success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheLe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarLe(rhs.Uint64())
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheLe scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheNe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheNe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheNe operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.ne(rhs.ciphertext)
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheNe success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheNe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarNe(rhs.Uint64())
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheNe scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func decryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
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
	plaintext, err := decryptValue(ct.ciphertext)
	if err != nil {
		logger.Error("decrypt failed", "err", err)
		return nil, err
	}
	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	bigIntValue := big.NewInt(0)
	bigIntValue.SetUint64(plaintext)
	bigIntValue.FillBytes(ret)
	return ret, nil
}

func decryptValue(ct *tfheCiphertext) (uint64, error) {
	v, err := ct.decrypt()
	return v.Uint64(), err
}

// If there are optimistic requires, check them by doing bitwise AND on all of them.
// That works, because we assume their values are either 0 or 1. If there is at least
// one 0, the result will be 0 (false).
func evaluateRemainingOptimisticRequires(environment EVMEnvironment) (bool, error) {
	requires := environment.GetFhevmData().optimisticRequires
	len := len(requires)
	defer func() { requires = make([]*tfheCiphertext, 0) }()
	if len != 0 {
		var cumulative *tfheCiphertext = requires[0]
		var err error
		for i := 1; i < len; i++ {
			cumulative, err = cumulative.bitand(requires[i])
			if err != nil {
				environment.GetLogger().Error("evaluateRemainingOptimisticRequires bitand failed", "err", err)
				return false, err
			}
		}
		result, err := decryptValue(cumulative)
		return result != 0, err
	}
	return true, nil
}

func castRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
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

	if !isValidType(input[32]) {
		logger.Error("invalid type to cast to")
		return nil, errors.New("invalid type provided")
	}
	castToType := fheUintType(input[32])

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, castToType), nil
	}

	res, err := ct.ciphertext.castTo(castToType)
	if err != nil {
		msg := "cast Run() error casting ciphertext to"
		logger.Error(msg, "type", castToType)
		return nil, errors.New(msg)
	}

	resHash := res.getHash()

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

func fhePubKeyRun(accessibleState EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	existing := accessibleState.GetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot)
	if existing != pksHash {
		msg := "fhePubKey FHE public key hash doesn't match one stored in state"
		accessibleState.GetLogger().Error(msg, "existing", existing.Hex(), "pksHash", pksHash.Hex())
		return nil, errors.New(msg)
	}
	// If we have a single byte with the value of 1, return as an EVM array. Otherwise, returh the raw bytes.
	if len(input) == 1 && input[0] == 1 {
		return toEVMBytes(pksBytes), nil
	} else {
		return pksBytes, nil
	}
}

func trivialEncryptRun(accessibleState EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := accessibleState.GetLogger()
	if len(input) != 33 {
		msg := "trivialEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := fheUintType(input[32])

	ct := new(tfheCiphertext).trivialEncrypt(valueToEncrypt, encryptToType)

	ctHash := ct.getHash()
	importCiphertext(accessibleState, ct)
	if accessibleState.IsCommitting() {
		logger.Info("trivialEncrypt success",
			"ctHash", ctHash.Hex(),
			"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}

func verifyCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if len(input) <= 1 {
		msg := "verifyCiphertext Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ctBytes := input[:len(input)-1]
	ctTypeByte := input[len(input)-1]
	if !isValidType(ctTypeByte) {
		msg := "verifyCiphertext Run() ciphertext type is invalid"
		logger.Error(msg, "type", ctTypeByte)
		return nil, errors.New(msg)
	}
	ctType := fheUintType(ctTypeByte)

	expectedSize, found := compactFheCiphertextSize[ctType]
	if !found || expectedSize != uint(len(ctBytes)) {
		msg := "verifyCiphertext Run() compact ciphertext size is invalid"
		logger.Error(msg, "type", ctTypeByte, "size", len(ctBytes), "expectedSize", expectedSize)
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ctType), nil
	}

	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(ctBytes, ctType)
	if err != nil {
		logger.Error("verifyCiphertext failed to deserialize input ciphertext",
			"err", err,
			"len", len(ctBytes),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
		return nil, err
	}
	ctHash := ct.getHash()
	importCiphertext(environment, ct)
	if environment.IsCommitting() {
		logger.Info("verifyCiphertext success",
			"ctHash", ctHash.Hex(),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
	}
	return ctHash.Bytes(), nil
}
