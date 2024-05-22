package fhevm

import (
	"fmt"
	"testing"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func TestTeeShlRun(t *testing.T) {
	signature := "teeShl(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 4},
		{tfhe.FheUint8, 2, 2, 8},
		{tfhe.FheUint16, 4283, 3, 34264},
		{tfhe.FheUint32, 1333337, 4, 21333392},
		{tfhe.FheUint64, 13333377777777777, 5, 426668088888888864},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeShl with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeShrRun(t *testing.T) {
	signature := "teeShr(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 2, 1070},
		{tfhe.FheUint32, 1333337, 3, 166667},
		{tfhe.FheUint64, 13333377777777777, 4, 833336111111111},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeShr with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeRotlRun(t *testing.T) {
	signature := "teeRotl(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 4},
		{tfhe.FheUint8, 4, 2, 16},
		{tfhe.FheUint16, 4283, 3, 34264},
		{tfhe.FheUint32, 1333337, 10, 1365337088},
		{tfhe.FheUint64, 13333377777777777, 22, 12158459430790237143},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeRotl with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeRotrRun(t *testing.T) {
	signature := "teeRotr(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 17},
		{tfhe.FheUint8, 4, 2, 1},
		{tfhe.FheUint16, 4283, 3, 25111},
		{tfhe.FheUint32, 1333337, 10, 373294358},
		{tfhe.FheUint64, 13333377777777777, 22, 7417925568713886648},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeRotr with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeBitAndRun(t *testing.T) {
	signature := "teeBitAnd(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheBool, 1, 0, 0},
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 57},
		{tfhe.FheUint32, 1333337, 1337, 25},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 8791859313},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeBitAnd with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeBitOrRun(t *testing.T) {
	signature := "teeBitOr(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheBool, 1, 0, 1},
		{tfhe.FheUint4, 2, 1, 3},
		{tfhe.FheUint8, 2, 1, 3},
		{tfhe.FheUint16, 4283, 1337, 5563},
		{tfhe.FheUint32, 1333337, 1337, 1334649},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333502363696241},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeBitOr with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeBitXorRun(t *testing.T) {
	signature := "teeBitXor(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheBool, 1, 0, 1},
		{tfhe.FheUint4, 2, 1, 3},
		{tfhe.FheUint8, 2, 1, 3},
		{tfhe.FheUint16, 4283, 1337, 5506},
		{tfhe.FheUint32, 1333337, 1337, 1334624},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333493571836928},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeBitXor with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeNegRun(t *testing.T) {
	signature := "teeNeg(uint256)"

	testcases := []struct {
		typ      tfhe.FheUintType
		chs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 254},
		{tfhe.FheUint8, 2, 254},
		{tfhe.FheUint16, 4283, 61253},
		{tfhe.FheUint32, 1333337, 4293633959},
		{tfhe.FheUint64, 13333377777777777, 18433410695931773839},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeNeg with %s", tc.typ), func(t *testing.T) {
			teeNegNotOperationHelper(t, tc.typ, tc.chs, tc.expected, signature)
		})
	}
}

func TestTeeNotRun(t *testing.T) {
	signature := "teeNot(uint256)"

	testcases := []struct {
		typ      tfhe.FheUintType
		chs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 253},
		{tfhe.FheUint8, 2, 253},
		{tfhe.FheUint16, 4283, 61252},
		{tfhe.FheUint32, 1333337, 4293633958},
		{tfhe.FheUint64, 13333377777777777, 18433410695931773838},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeNot with %s", tc.typ), func(t *testing.T) {
			teeNegNotOperationHelper(t, tc.typ, tc.chs, tc.expected, signature)
		})
	}
}
