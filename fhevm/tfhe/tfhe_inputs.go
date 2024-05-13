package tfhe

/*
#include "tfhe_wrappers.h"
*/
import "C"
import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Represents an TFHE input.
type TfheInputs struct {
	Index int
	Ciphertexts []*TfheCiphertext
	Serialization []byte
	Hash          *common.Hash
}


// Deserializes a TFHE ciphertext.
func (input *TfheInputs) Verify(in []byte) error {
	input.Index = 0
	input.deserialize(in)
	input.computeHash()
	return nil
}

// Deserializes a TFHE ciphertext.
func (input *TfheInputs) Empty(in []byte) error {
	input.Index = 0
	input.Ciphertexts = make([]*TfheCiphertext, 0)
	input.computeHash()
	return nil
}

func (input *TfheInputs) deserialize(in []byte) error {
		ptr, length := C.deserialize_compact_list(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint160 ciphertext deserialization failed")
		}
		var err error
		input.Serialization, err = serializeCompactList(ptr, FheUint160)

		input.Ciphertexts = make([]*TfheCiphertext, length)
		for i := 0; i < length; i++ {
			ct := new(TfheCiphertext)
			ct.FheUintType = FheUint160
			ct.Serialization, err = serialize(ptr[i], FheUint160)
			ct.computeHash()
			input.Ciphertexts = append(input.Ciphertexts, ct)
		}
		C.destroy_compact_fhe_uint160_list(ptr)
		if err != nil {
			return err
		}
}

// Deserializes a TFHE ciphertext.
func (input *TfheInputs) Next(t FheUintType) *TfheCiphertext {
	if (len(input.Ciphertexts) > input.Index) {
		ct := input.Ciphertexts[input.Index]
		input.Index += 1
		if (ct.FheUintType == t) {
			return ct
		} else {
			castedCt, err := ct.CastTo(t)
			if (err != nil) {
				castedCt = new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), t)
			}
			input.Ciphertexts[input.Index] = castedCt
			return castedCt;
		}
	} else {
		ct := new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), t)
		return ct
	}
}

func (ct *TfheInputs) computeHash() {
	hash := common.BytesToHash(crypto.Keccak256(ct.Serialization))
	ct.Hash = &hash
}

func (ct *TfheInputs) GetHash() common.Hash {
	if ct.Hash != nil {
		return *ct.Hash
	}
	ct.computeHash()
	return *ct.Hash
}