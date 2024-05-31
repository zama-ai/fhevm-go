package tee

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var key *ecies.PrivateKey

func init() {
	// For now, we hardcode the private key that will be used in the TEE.
	// We will change this to use a secure enclave key generation mechanism.
	hexKey := "4a3f9d7b12e8acef2f8a561e3c3b9f9dd3e8a3b1f4de4e8d243a45ad4b7e34cf"
	ecdsaKey, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		panic(err)
	}
	key = ecies.ImportECDSA(ecdsaKey)
	initCiphertextSizes()
}

type TeePlaintext struct {
	// Value is the bytes representation of the plaintext.
	Value []byte
	// Type is the type of the plaintext.
	FheUintType tfhe.FheUintType
	// Address is used as zkPoK on the TEE.
	Address common.Address
}

func NewTeePlaintext(plaintext []byte, fheType tfhe.FheUintType, address common.Address) TeePlaintext {
	return TeePlaintext{
		plaintext,
		fheType,
		address,
	}
}

// AsUint8 returns the plaintext as a uint8.
func (sp TeePlaintext) AsUint8() uint8 {
	if sp.FheUintType != tfhe.FheUint4 && sp.FheUintType != tfhe.FheUint8 {
		panic(fmt.Sprintf("Expected FheUint4 or FheUint8, got %s", sp.FheUintType))
	}

	return sp.Value[0]
}

// AsUint16 returns the plaintext as a uint16.
func (sp TeePlaintext) AsUint16() uint16 {
	if sp.FheUintType != tfhe.FheUint16 {
		panic(fmt.Sprintf("Expected FheUint16, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint16(sp.Value)
}

// AsUint32 returns the plaintext as a uint32.
func (sp TeePlaintext) AsUint32() uint32 {
	if sp.FheUintType != tfhe.FheUint32 {
		panic(fmt.Sprintf("Expected FheUint32, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint32(sp.Value)
}

// AsUint64 returns the plaintext as a uint64.
func (sp TeePlaintext) AsUint64() uint64 {
	if sp.FheUintType != tfhe.FheUint64 {
		panic(fmt.Sprintf("expected FheUint64, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint64(sp.Value)
}

func Encrypt(teeCt TeePlaintext) (tfhe.TfheCiphertext, error) {
	// Encode the TeePlaintext struct as a byte array using JSON.
	// This will be used as the plaintext for the ECIES encryption.
	//
	// We only require that the implementation of this JSON is deterministic,
	// which is the case for golang's standard library.
	bz, err := json.Marshal(teeCt)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}

	// Encrypt the plaintext using the public key.
	ciphertext, err := ecies.Encrypt(rand.Reader, &key.PublicKey, bz, nil, nil)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	hash := common.BytesToHash(crypto.Keccak256(ciphertext))
	return tfhe.TfheCiphertext{
		FheUintType:   teeCt.FheUintType,
		Serialization: ciphertext,
		Hash:          &hash,
	}, nil
}

func Decrypt(ct *tfhe.TfheCiphertext) (TeePlaintext, error) {
	// Decrypt the ciphertext using the private key.
	plaintextBz, err := key.Decrypt(ct.Serialization, nil, nil)
	if err != nil {
		return TeePlaintext{}, err
	}

	// Decode the plaintext bytes into a TeePlaintext struct.
	var plaintext TeePlaintext
	err = json.Unmarshal(plaintextBz, &plaintext)
	if err != nil {
		return TeePlaintext{}, err
	}

	return plaintext, nil
}

func GetTeeCiphertextSize(t tfhe.FheUintType) (size uint, found bool) {
	size, found = teeCiphertextSize[t]
	return
}

// Compact TFHE ciphertext sizes by type, in bytes.
var teeCiphertextSize map[tfhe.FheUintType]uint

func initCiphertextSizes() {
	teeCiphertextSize = make(map[tfhe.FheUintType]uint)

	teeCiphertextSize[tfhe.FheBool] = uint(len(TeeEncryptAndSerialize(0, tfhe.FheBool)))
	teeCiphertextSize[tfhe.FheUint4] = uint(len(TeeEncryptAndSerialize(0, tfhe.FheUint4)))
	teeCiphertextSize[tfhe.FheUint8] = uint(len(TeeEncryptAndSerialize(0, tfhe.FheUint8)))
	teeCiphertextSize[tfhe.FheUint16] = uint(len(TeeEncryptAndSerialize(0, tfhe.FheUint16)))
	teeCiphertextSize[tfhe.FheUint32] = uint(len(TeeEncryptAndSerialize(0, tfhe.FheUint32)))
	teeCiphertextSize[tfhe.FheUint64] = uint(len(TeeEncryptAndSerialize(0, tfhe.FheUint64)))
	teeCiphertextSize[tfhe.FheUint160] = uint(len(TeeEncryptAndSerialize(0, tfhe.FheUint160)))
}

func TeeEncryptAndSerialize(value uint64, fheUintType tfhe.FheUintType) []byte {
	resultBz, err := MarshalTfheType(value, fheUintType)
	if err != nil {
		panic(err)
	}

	ciphertext, err := Encrypt(NewTeePlaintext(resultBz, fheUintType, common.Address{}))
	if err != nil {
		panic(err)
	}

	return ciphertext.Serialization
}

// MarshalTfheType converts a any to a byte slice
func MarshalTfheType(value any, typ tfhe.FheUintType) ([]byte, error) {
	switch value := any(value).(type) {
	case uint64:
		switch typ {
		case tfhe.FheBool:
			resultBz := make([]byte, 1)
			resultBz[0] = byte(value)
			return resultBz, nil
		case tfhe.FheUint4:
			return []byte{byte(value)}, nil
		case tfhe.FheUint8:
			resultBz := []byte{byte(value)}
			return resultBz, nil
		case tfhe.FheUint16:
			resultBz := make([]byte, 2)
			binary.BigEndian.PutUint16(resultBz, uint16(value))
			return resultBz, nil
		case tfhe.FheUint32:
			resultBz := make([]byte, 4)
			binary.BigEndian.PutUint32(resultBz, uint32(value))
			return resultBz, nil
		case tfhe.FheUint64:
			resultBz := make([]byte, 8)
			binary.BigEndian.PutUint64(resultBz, value)
			return resultBz, nil
		case tfhe.FheUint160:
			resultBz := make([]byte, 8)
			binary.BigEndian.PutUint64(resultBz, value)
			return resultBz, nil
		default:
			return nil,
				fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	case bool:
		resultBz := make([]byte, 1)
		if value {
			resultBz[0] = 1
		} else {
			resultBz[0] = 0
		}
		return resultBz, nil
	case *big.Int:
		resultBz := value.Bytes()
		return resultBz, nil
	default:
		return nil,
			fmt.Errorf("unsupported value type: %s", value)
	}
}
