package fhevm

import (
	"fmt"
	"testing"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func TestTeeLeRun(t *testing.T) {
	signature := "teeLe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 0},
		{tfhe.FheUint32, 1333337, 1337, 0},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 0},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeLe with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeLtRun(t *testing.T) {
	signature := "teeLt(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 0},
		{tfhe.FheUint32, 1333337, 1337, 0},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 0},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeLt with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeEqRun(t *testing.T) {
	signature := "teeEq(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 0},
		{tfhe.FheUint32, 1333337, 1337, 0},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 0},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeEq with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeGeRun(t *testing.T) {
	signature := "teeGe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1},
		{tfhe.FheUint32, 1333337, 1337, 1},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 1},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeGe with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeGtRun(t *testing.T) {
	signature := "teeGt(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1},
		{tfhe.FheUint32, 1333337, 1337, 1},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 1},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeGt with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeNeRun(t *testing.T) {
	signature := "teeNe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1},
		{tfhe.FheUint32, 1333337, 1337, 1},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 1},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeNe with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeMinRun(t *testing.T) {
	signature := "teeMin(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1337},
		{tfhe.FheUint32, 1333337, 1337, 1337},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 133377777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMin with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeMaxRun(t *testing.T) {
	signature := "teeMax(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 2},
		{tfhe.FheUint8, 2, 1, 2},
		{tfhe.FheUint16, 4283, 1337, 4283},
		{tfhe.FheUint32, 1333337, 1337, 1333337},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333377777777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMax with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeSelectRun(t *testing.T) {
	signature := "teeSelect(uint256,uint256,uint256)"

	testcases := []struct {
		typ      tfhe.FheUintType
		fhs      bool
		shs      uint64
		ths      uint64
		expected uint64
	}{
		{tfhe.FheUint4, true, 2, 1, 2},
		{tfhe.FheUint8, true, 2, 1, 2},
		{tfhe.FheUint16, true, 4283, 1337, 4283},
		{tfhe.FheUint32, true, 1333337, 1337, 1333337},
		{tfhe.FheUint64, true, 13333377777777777, 133377777777, 13333377777777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeSelect with %s", tc.typ), func(t *testing.T) {
			teeSelectHelper(t, tc.typ, tc.fhs, tc.shs, tc.ths, tc.expected, signature)
		})
	}
}
