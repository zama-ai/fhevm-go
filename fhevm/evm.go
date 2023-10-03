package fhevm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
	return binary.BigEndian.Uint32(crypto.Keccak256([]byte(input))[0:4])
}

func isScalarOp(environment *EVMEnvironment, input []byte) (bool, error) {
	if len(input) != 65 {
		return false, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	isScalar := (input[64] == 1)
	return isScalar, nil
}

func getVerifiedCiphertext(environment *EVMEnvironment, ciphertextHash common.Hash) *verifiedCiphertext {
	return getVerifiedCiphertextFromEVM(*environment, ciphertextHash)
}

func get2VerifiedOperands(environment *EVMEnvironment, input []byte) (lhs *verifiedCiphertext, rhs *verifiedCiphertext, err error) {
	if len(input) != 65 {
		return nil, nil, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	lhs = getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	rhs = getVerifiedCiphertext(environment, common.BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	err = nil
	return
}

func getScalarOperands(environment *EVMEnvironment, input []byte) (lhs *verifiedCiphertext, rhs *big.Int, err error) {
	if len(input) != 65 {
		return nil, nil, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	lhs = getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	rhs = &big.Int{}
	rhs.SetBytes(input[32:64])
	return
}

func importCiphertextToEVMAtDepth(environment *EVMEnvironment, ct *tfheCiphertext, depth int) *verifiedCiphertext {
	existing, ok := (*environment).GetFhevmData().verifiedCiphertexts[ct.getHash()]
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
		(*environment).GetFhevmData().verifiedCiphertexts[ct.getHash()] = new
		return new
	}
}

func importCiphertextToEVM(environment *EVMEnvironment, ct *tfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVMAtDepth(environment, ct, (*environment).GetDepth())
}

func importCiphertext(environment *EVMEnvironment, ct *tfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVM(environment, ct)
}

func importRandomCiphertext(environment *EVMEnvironment, t fheUintType) []byte {
	nextCtHash := &(*environment).GetFhevmData().nextCiphertextHashOnGasEst
	ctHashBytes := crypto.Keccak256(nextCtHash.Bytes())
	handle := common.BytesToHash(ctHashBytes)
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
