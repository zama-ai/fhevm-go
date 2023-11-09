package fhevm

import (
	"math/big"

	"github.com/holiman/uint256"
)

type EVMEnvironment interface {
	// StateDB related functions
	GetState(Address, Hash) Hash
	SetState(Address, Hash, Hash)
	GetNonce(Address) uint64
	AddBalance(Address, *big.Int)
	GetBalance(Address) *big.Int

	Suicide(Address) bool

	// EVM call stack depth
	GetDepth() int

	// EVM Logger
	GetLogger() Logger

	// TODO: clarify meaning of the following
	IsCommitting() bool
	IsEthCall() bool
	IsReadOnly() bool

	CreateContract(caller Address, code []byte, gas uint64, value *big.Int, address Address) ([]byte, Address, uint64, error)
	CreateContract2(caller Address, code []byte, codeHash Hash, gas uint64, value *big.Int, address Address) ([]byte, Address, uint64, error)

	FhevmData() *FhevmData
	FhevmParams() *FhevmParams
}

type FhevmData struct {
	// A map from a ciphertext hash to itself and stack depth at which it is verified
	verifiedCiphertexts map[Hash]*verifiedCiphertext

	// All optimistic requires encountered up to that point in the txn execution
	optimisticRequires []*tfheCiphertext

	nextCiphertextHashOnGasEst uint256.Int
}

func NewFhevmData() FhevmData {
	return FhevmData{
		verifiedCiphertexts: make(map[Hash]*verifiedCiphertext),
		optimisticRequires:  make([]*tfheCiphertext, 0),
	}
}
