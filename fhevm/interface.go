package fhevm

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type EVMEnvironment interface {
	// StateDB related functions
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
	GetNonce(common.Address) uint64

	// EVM call stack depth
	GetDepth() int

	// EVM Logger
	GetLogger() Logger

	// TODO: clarify meaning of the following
	IsCommitting() bool
	IsEthCall() bool
	IsReadOnly() bool

	CreateContract(caller common.Address, code []byte, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error)
	CreateContract2(caller common.Address, code []byte, codeHash common.Hash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error)

	GetFhevmData() *FhevmData
}

type FhevmData struct {
	// A map from a ciphertext hash to itself and stack depth at which it is verified
	verifiedCiphertexts map[common.Hash]*verifiedCiphertext

	// All optimistic requires encountered up to that point in the txn execution
	optimisticRequires []*tfheCiphertext

	nextCiphertextHashOnGasEst uint256.Int
}

func NewFhevmData() FhevmData {
	return FhevmData{
		verifiedCiphertexts: make(map[common.Hash]*verifiedCiphertext),
		optimisticRequires:  make([]*tfheCiphertext, 0),
	}
}
