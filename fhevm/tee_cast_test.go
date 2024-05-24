package fhevm

import (
	"fmt"
	"testing"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func TestTeeCast(t *testing.T) {
	signature := "teeCast(uint256,bytes1)"

	testcases := []struct {
		description string
		intyp       tfhe.FheUintType
		outtyp      tfhe.FheUintType
		input       uint64
		expected    uint64
	}{
		{"Tee4Cast8", tfhe.FheUint4, tfhe.FheUint8, 2, 2},
		{"Tee4Cast16", tfhe.FheUint4, tfhe.FheUint16, 2, 2},
		{"Tee4Cast32", tfhe.FheUint4, tfhe.FheUint32, 2, 2},
		{"Tee4Cast64", tfhe.FheUint4, tfhe.FheUint64, 2, 2},
		{"Tee8Cast4", tfhe.FheUint8, tfhe.FheUint4, 2, 2},
		{"Tee8Cast16", tfhe.FheUint8, tfhe.FheUint16, 2, 2},
		{"Tee8Cast32", tfhe.FheUint8, tfhe.FheUint32, 2, 2},
		{"Tee8Cast64", tfhe.FheUint8, tfhe.FheUint64, 2, 2},
		{"Tee16Cast4", tfhe.FheUint16, tfhe.FheUint4, 4283, 11},
		{"Tee16Cast8", tfhe.FheUint16, tfhe.FheUint8, 4283, 187},
		{"Tee16Cast32", tfhe.FheUint16, tfhe.FheUint32, 4283, 4283},
		{"Tee16Cast64", tfhe.FheUint16, tfhe.FheUint64, 4283, 4283},
		{"Tee32Cast4", tfhe.FheUint32, tfhe.FheUint4, 1333337, 9},
		{"Tee32Cast8", tfhe.FheUint32, tfhe.FheUint8, 1333337, 89},
		{"Tee32Cast16", tfhe.FheUint32, tfhe.FheUint16, 1333337, 22617},
		{"Tee32Cast64", tfhe.FheUint32, tfhe.FheUint64, 1333337, 1333337},
		{"Tee64Cast4", tfhe.FheUint64, tfhe.FheUint4, 13333377777777777, 1},
		{"Tee64Cast8", tfhe.FheUint64, tfhe.FheUint8, 13333377777777777, 113},
		{"Tee64Cast16", tfhe.FheUint64, tfhe.FheUint16, 13333377777777777, 48241},
		{"Tee64Cast32", tfhe.FheUint64, tfhe.FheUint32, 13333377777777777, 3994664049},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeCast with %s", tc.description), func(t *testing.T) {
			teeCastHelper(t, tc.intyp, tc.outtyp, tc.input, tc.expected, signature)
		})
	}
}
