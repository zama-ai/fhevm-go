package fhevm

import (
	"fmt"
	"testing"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func TestTeeAddRun(t *testing.T) {
	signature := "teeAdd(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 3},
		{tfhe.FheUint8, 2, 1, 3},
		{tfhe.FheUint16, 4283, 1337, 5620},
		{tfhe.FheUint32, 1333337, 1337, 1334674},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333511155555554},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeAdd with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeSubRun(t *testing.T) {
	signature := "teeSub(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 2946},
		{tfhe.FheUint32, 1333337, 1337, 1332000},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333244400000000},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeSub with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeMulRun(t *testing.T) {
	signature := "teeMul(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 3, 6},
		{tfhe.FheUint8, 2, 3, 6},
		{tfhe.FheUint16, 169, 5, 845},
		{tfhe.FheUint32, 137, 17, 2329},
		{tfhe.FheUint64, 137777, 17, 2342209},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMul with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeDivRun(t *testing.T) {
	signature := "teeDiv(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 2},
		{tfhe.FheUint8, 2, 1, 2},
		{tfhe.FheUint16, 4283, 1337, 3},
		{tfhe.FheUint32, 1333337, 1337, 997},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 99967},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeDiv with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeRemRun(t *testing.T) {
	signature := "teeRem(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 272},
		{tfhe.FheUint32, 1333337, 1337, 348},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 1466744418},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeRem with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}
