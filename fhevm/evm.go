package fhevm

import (
	"log/slog"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/fhevm/crypto"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var protectedStorageAddrCallerAddr common.Address
var defaultProtectedStorageAddrCallerAddr = []byte{93}

// Set the addr to be used as caller when creating protected storage contracts
func SetProtectedStorageAddrCallerAddr(addr []byte) {
	protectedStorageAddrCallerAddr = common.BytesToAddress(addr)
}

func init() {
	SetProtectedStorageAddrCallerAddr(defaultProtectedStorageAddrCallerAddr)
}

// A Logger interface for the EVM.
type Logger interface {
	Debug(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
}

// A default Logger implementation that logs to stdout.
type DefaultLogger struct {
	slogger *slog.Logger
}

func NewDefaultLogger() Logger {
	logger := &DefaultLogger{}
	logger.slogger = slog.Default().With("module", "fhevm-go")
	return logger
}

func (l *DefaultLogger) Debug(msg string, keyvals ...interface{}) {
	l.slogger.Debug(msg, keyvals...)
}

func (l *DefaultLogger) Info(msg string, keyvals ...interface{}) {
	l.slogger.Info(msg, keyvals...)
}

func (l *DefaultLogger) Error(msg string, keyvals ...interface{}) {
	l.slogger.Error(msg, keyvals...)
}

func getVerifiedCiphertext(environment EVMEnvironment, ciphertextHash common.Hash) *verifiedCiphertext {
	return getVerifiedCiphertextFromEVM(environment, ciphertextHash)
}

func importCiphertextToEVMAtDepth(environment EVMEnvironment, ct *tfhe.TfheCiphertext, depth int) *verifiedCiphertext {
	existing, ok := environment.FhevmData().verifiedCiphertexts[ct.GetHash()]
	if ok {
		existing.verifiedDepths.add(depth)
		return existing
	} else {
		verifiedDepths := newDepthSet()
		verifiedDepths.add(depth)
		new := &verifiedCiphertext{
			verifiedDepths,
			ct,
		}
		environment.FhevmData().verifiedCiphertexts[ct.GetHash()] = new
		return new
	}
}

func importInputs(environment EVMEnvironment, inputs *tfhe.TfheInputs) *verifiedInputs {
	depth := environment.GetDepth()

	existing, ok := environment.FhevmData().verifiedInputs[inputs.GetHash()]
	if ok {
		existing.verifiedDepths.add(depth)
		return existing
	} else {
		verifiedDepths := newDepthSet()
		verifiedDepths.add(depth)
		new := &verifiedInputs{
			verifiedDepths,
			inputs,
		}
		environment.FhevmData().verifiedInputs[inputs.GetHash()] = new
		return new
	}
}

func importCiphertextToEVMAtDepth(environment EVMEnvironment, ct *tfhe.TfheCiphertext, depth int) *verifiedCiphertext {
	existing, ok := environment.FhevmData().verifiedCiphertexts[ct.GetHash()]
	if ok {
		existing.verifiedDepths.add(depth)
		return existing
	} else {
		verifiedDepths := newDepthSet()
		verifiedDepths.add(depth)
		new := &verifiedCiphertext{
			verifiedDepths,
			ct,
		}
		environment.FhevmData().verifiedCiphertexts[ct.GetHash()] = new
		return new
	}
}

func importCiphertextToEVM(environment EVMEnvironment, ct *tfhe.TfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVMAtDepth(environment, ct, environment.GetDepth())
}

func importCiphertext(environment EVMEnvironment, ct *tfhe.TfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVM(environment, ct)
}

func importRandomCiphertext(environment EVMEnvironment, t tfhe.FheUintType) []byte {
	nextCtHash := &environment.FhevmData().nextCiphertextHashOnGasEst
	ctHashBytes := crypto.Keccak256(nextCtHash.Bytes())
	handle := common.BytesToHash(ctHashBytes)
	ct := new(tfhe.TfheCiphertext)
	ct.FheUintType = t
	ct.Hash = &handle
	importCiphertext(environment, ct)
	temp := nextCtHash.Clone()
	nextCtHash.Add(temp, uint256.NewInt(1))
	return ct.GetHash().Bytes()
}

func InitFhevm(accessibleState EVMEnvironment) {
	persistFhePubKeyHash(accessibleState)
}

func persistFhePubKeyHash(accessibleState EVMEnvironment) {
	existing := accessibleState.GetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot)
	if newInt(existing[:]).IsZero() {
		var pksHash = tfhe.GetPksHash()
		accessibleState.SetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot, pksHash)
	}
}

func Create(evm EVMEnvironment, caller common.Address, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller, evm.GetNonce(caller))
	protectedStorageAddr := fhevm_crypto.CreateProtectedStorageContractAddress(contractAddr)
	_, _, leftOverGas, err = evm.CreateContract(protectedStorageAddrCallerAddr, nil, gas, big.NewInt(0), protectedStorageAddr)
	if err != nil {
		ret = nil
		contractAddr = common.Address{}
		return
	}
	// TODO: consider reverting changes to `protectedStorageAddr` if actual contract creation fails.
	return evm.CreateContract(caller, code, leftOverGas, value, contractAddr)
}

func Create2(evm EVMEnvironment, caller common.Address, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeHash := crypto.Keccak256Hash(code)
	contractAddr = crypto.CreateAddress2(caller, salt.Bytes32(), codeHash.Bytes())
	protectedStorageAddr := fhevm_crypto.CreateProtectedStorageContractAddress(contractAddr)
	_, _, leftOverGas, err = evm.CreateContract2(protectedStorageAddrCallerAddr, nil, common.Hash{}, gas, big.NewInt(0), protectedStorageAddr)
	if err != nil {
		ret = nil
		contractAddr = common.Address{}
		return
	}
	// TODO: consider reverting changes to `protectedStorageAddr` if actual contract creation fails.
	return evm.CreateContract2(caller, code, codeHash, leftOverGas, endowment, contractAddr)
}
