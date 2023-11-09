package fhevm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
)

// A Logger interface for the EVM.
type Logger interface {
	Debug(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
}

// A default Logger implementation that logs to stdout.
type DefaultLogger struct{}

func toString(keyvals ...interface{}) (ret string) {
	for _, element := range keyvals {
		ret += fmt.Sprintf("%v", element) + " "
	}
	return
}

func (*DefaultLogger) Debug(msg string, keyvals ...interface{}) {
	fmt.Println("Debug: "+msg, toString(keyvals...))
}

func (*DefaultLogger) Info(msg string, keyvals ...interface{}) {
	fmt.Println("Info: "+msg, toString(keyvals...))
}

func (*DefaultLogger) Error(msg string, keyvals ...interface{}) {
	fmt.Println("Error: "+msg, toString(keyvals...))
}

func makeKeccakSignature(input string) uint32 {
	return binary.BigEndian.Uint32(Keccak256([]byte(input))[0:4])
}

func isScalarOp(input []byte) (bool, error) {
	if len(input) != 65 {
		return false, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	isScalar := (input[64] == 1)
	return isScalar, nil
}

func getVerifiedCiphertext(environment EVMEnvironment, ciphertextHash Hash) *verifiedCiphertext {
	return getVerifiedCiphertextFromEVM(environment, ciphertextHash)
}

func get2VerifiedOperands(environment EVMEnvironment, input []byte) (lhs *verifiedCiphertext, rhs *verifiedCiphertext, err error) {
	if len(input) != 65 {
		return nil, nil, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	lhs = getVerifiedCiphertext(environment, BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	rhs = getVerifiedCiphertext(environment, BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	err = nil
	return
}

func getScalarOperands(environment EVMEnvironment, input []byte) (lhs *verifiedCiphertext, rhs *big.Int, err error) {
	if len(input) != 65 {
		return nil, nil, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	lhs = getVerifiedCiphertext(environment, BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	rhs = &big.Int{}
	rhs.SetBytes(input[32:64])
	return
}

func importCiphertextToEVMAtDepth(environment EVMEnvironment, ct *tfheCiphertext, depth int) *verifiedCiphertext {
	existing, ok := environment.FhevmData().verifiedCiphertexts[ct.getHash()]
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
		environment.FhevmData().verifiedCiphertexts[ct.getHash()] = new
		return new
	}
}

func importCiphertextToEVM(environment EVMEnvironment, ct *tfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVMAtDepth(environment, ct, environment.GetDepth())
}

func importCiphertext(environment EVMEnvironment, ct *tfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVM(environment, ct)
}

func importRandomCiphertext(environment EVMEnvironment, t FheUintType) []byte {
	nextCtHash := &environment.FhevmData().nextCiphertextHashOnGasEst
	ctHashBytes := Keccak256(nextCtHash.Bytes())
	handle := BytesToHash(ctHashBytes)
	ct := new(tfheCiphertext)
	ct.fheUintType = t
	ct.hash = &handle
	importCiphertext(environment, ct)
	temp := nextCtHash.Clone()
	nextCtHash.Add(temp, uint256.NewInt(1))
	return ct.getHash().Bytes()
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// Return a memory with a layout that matches the `bytes` EVM type, namely:
//   - 32 byte integer in big-endian order as length
//   - the actual bytes in the `bytes` value
//   - add zero byte padding until nearest multiple of 32
func toEVMBytes(input []byte) []byte {
	arrLen := uint64(len(input))
	lenBytes32 := uint256.NewInt(arrLen).Bytes32()
	ret := make([]byte, 0, arrLen+32)
	ret = append(ret, lenBytes32[:]...)
	ret = append(ret, input...)
	return ret
}

func InitFhevm(accessibleState EVMEnvironment) {
	persistFhePubKeyHash(accessibleState)
}

func persistFhePubKeyHash(accessibleState EVMEnvironment) {
	existing := accessibleState.GetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot)
	if newInt(existing[:]).IsZero() {
		accessibleState.SetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot, pksHash)
	}
}

// apply padding to slice to the multiple of 32
func padArrayTo32Multiple(input []byte) []byte {
	modRes := len(input) % 32
	if modRes > 0 {
		padding := 32 - modRes
		for padding > 0 {
			padding--
			input = append(input, 0x0)
		}
	}
	return input
}

func Create(evm EVMEnvironment, caller Address, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr Address, leftOverGas uint64, err error) {
	contractAddr = CreateAddress(caller, evm.GetNonce(caller))
	protectedStorageAddr := CreateProtectedStorageContractAddress(contractAddr)
	_, _, leftOverGas, err = evm.CreateContract(caller, nil, gas, big.NewInt(0), protectedStorageAddr)
	if err != nil {
		ret = nil
		contractAddr = Address{}
		return
	}
	// TODO: consider reverting changes to `protectedStorageAddr` if actual contract creation fails.
	return evm.CreateContract(caller, code, leftOverGas, value, contractAddr)
}

func Create2(evm EVMEnvironment, caller Address, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) (ret []byte, contractAddr Address, leftOverGas uint64, err error) {
	codeHash := Keccak256Hash(code)
	contractAddr = CreateAddress2(caller, salt.Bytes32(), codeHash.Bytes())
	protectedStorageAddr := CreateProtectedStorageContractAddress(contractAddr)
	_, _, leftOverGas, err = evm.CreateContract2(caller, nil, Hash{}, gas, big.NewInt(0), protectedStorageAddr)
	if err != nil {
		ret = nil
		contractAddr = Address{}
		return
	}
	// TODO: consider reverting changes to `protectedStorageAddr` if actual contract creation fails.
	return evm.CreateContract2(caller, code, codeHash, leftOverGas, endowment, contractAddr)
}
