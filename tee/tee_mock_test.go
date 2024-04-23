package tee_test

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"pgregory.net/rapid"
)

var teePlaintextGen *rapid.Generator[tee.TeePlaintext] = rapid.Custom(func(t *rapid.T) tee.TeePlaintext {
	bz := rapid.SliceOf(rapid.Byte()).Draw(t, "bz")
	fheType := tfhe.FheUintType(rapid.Uint8().Draw(t, "fheType"))
	address := common.Address(rapid.SliceOfN(rapid.Byte(), common.AddressLength, common.AddressLength).Draw(t, "address"))
	return tee.NewTeePlaintext(bz, fheType, address)
})

func compareTeePlaintexts(a, b tee.TeePlaintext) bool {
	return bytes.Equal(a.Value, b.Value) && a.FheUintType == b.FheUintType && a.Address == b.Address
}

func TestRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := teePlaintextGen.Draw(t, "a")

		// Encrypt -> Decrypt round trip
		b, err := tee.Encrypt(a)
		if err != nil {
			t.Fatal(err)
		}
		c, err := tee.Decrypt(&b)
		if err != nil {
			t.Fatal(err)
		}
		if !compareTeePlaintexts(a, c) {
			t.Fatalf("expected %v, got %v", a, c)
		}
	})
}

func TestUniqueCiphertexts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := teePlaintextGen.Draw(t, "a")

		// Encrypt twice the same plaintext
		b, err := tee.Encrypt(a)
		if err != nil {
			t.Fatal(err)
		}
		c, err := tee.Encrypt(a)
		if err != nil {
			t.Fatal(err)
		}

		// Make sure the ciphertexts are different
		if bytes.Equal(b.Serialization, c.Serialization) {
			t.Fatalf("expected different ciphertexts, got %v", b)
		}

		// Make sure the hashes (handles) are different
		if bytes.Equal(b.GetHash().Bytes(), c.GetHash().Bytes()) {
			t.Fatalf("expected different hashes, got %v", b.GetHash())
		}
	})
}
