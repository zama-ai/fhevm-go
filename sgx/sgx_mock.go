package sgx

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var key *ecies.PrivateKey

func init() {
	// For now, we hardcode the private key that will be used in the SGX.
	// We will change this to use a secure enclave key generation mechanism.
	hexKey := "4a3f9d7b12e8acef2f8a561e3c3b9f9dd3e8a3b1f4de4e8d243a45ad4b7e34cf"
	ecdsaKey, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		panic(err)
	}
	key = ecies.ImportECDSA(ecdsaKey)
}

type SgxPlaintext struct {
	Plaintext []byte
	Type      tfhe.FheUintType
	// Address is used as zkPoK on the SGX.
	Address common.Address
}

func NewSgxPlaintext(plaintext []byte, fheType tfhe.FheUintType, address common.Address) SgxPlaintext {
	return SgxPlaintext{
		plaintext,
		fheType,
		address,
	}
}

func ToTfheCiphertext(sgxCt SgxPlaintext) (tfhe.TfheCiphertext, error) {
	// Encode the SgxPlaintext struct as a byte array.
	// This will be used as the plaintext.
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(sgxCt)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}

	// Encrypt the plaintext using the public key.
	ciphertext, err := ecies.Encrypt(rand.Reader, &key.PublicKey, buf.Bytes(), nil, nil)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	hash := common.BytesToHash(crypto.Keccak256(ciphertext))
	return tfhe.TfheCiphertext{
		FheUintType:   sgxCt.Type,
		Serialization: ciphertext,
		Hash:          &hash,
	}, nil
}

func FromTfheCiphertext(ct *tfhe.TfheCiphertext) (SgxPlaintext, error) {
	// Decrypt the ciphertext using the private key.
	plaintext, err := key.Decrypt(ct.Serialization, nil, nil)
	if err != nil {
		return SgxPlaintext{}, err
	}

	// Decode the plaintext into a SgxPlaintext struct.
	buf := bytes.NewReader(plaintext)
	var sgxCt SgxPlaintext
	err = gob.NewDecoder(buf).Decode(&sgxCt)
	if err != nil {
		return SgxPlaintext{}, err
	}

	return sgxCt, nil
}
