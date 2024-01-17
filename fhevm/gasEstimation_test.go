package fhevm

import (
	"testing"
	"time"
)

type operation func(FheUintType)

const numBenchmarkRuns = 5

func convertInGas(t *testing.T, name string, elapsed [numBenchmarkRuns]time.Duration) {
	lowest := elapsed[0]

	// Find the lowest duration in the array
	for i := 1; i < numBenchmarkRuns; i++ {
		if elapsed[i] < lowest {
			lowest = elapsed[i]
		}
	}

	gasUsed := int64(lowest) / 1000 // 1s = 1,000,000 gas
	gasUsed = gasUsed / 7 * 10      // 0.7s = 1,000,000 gas
	gasUsed = gasUsed / 1000        // Divide to round it

	t.Logf("%s in %s => %d", name, lowest, gasUsed*1000)
}

func runTest(t *testing.T, name string, fn operation, bits string, fheUintType FheUintType) {
	var elapsed [numBenchmarkRuns]time.Duration
	n := 0
	for n < numBenchmarkRuns {
		start := time.Now()
		fn(fheUintType)
		elapsed[n] = time.Since(start)
		n += 1
	}
	convertInGas(t, name+bits, elapsed)
}

func estimateTests(t *testing.T, name string, fn operation) {
	runTest(t, name, fn, "8", FheUint8)
	runTest(t, name, fn, "16", FheUint16)
	runTest(t, name, fn, "32", FheUint32)
}

func TestGasEstimation(t *testing.T) {
	estimateTests(t, "not", func(fheUintType FheUintType) { FheNot(t, fheUintType, false) })

	estimateTests(t, "and", func(fheUintType FheUintType) { FheBitAnd(t, fheUintType, false) })

	estimateTests(t, "eq", func(fheUintType FheUintType) { FheEq(t, fheUintType, false) })
	estimateTests(t, "ScalarEq", func(fheUintType FheUintType) { FheEq(t, fheUintType, true) })

	estimateTests(t, "shr", func(fheUintType FheUintType) { FheShr(t, fheUintType, false) })
	estimateTests(t, "ScalarShr", func(fheUintType FheUintType) { FheShr(t, fheUintType, true) })

	estimateTests(t, "min", func(fheUintType FheUintType) { FheMin(t, fheUintType, false) })
	estimateTests(t, "ScalarMin", func(fheUintType FheUintType) { FheMin(t, fheUintType, true) })

	estimateTests(t, "add", func(fheUintType FheUintType) { FheAdd(t, fheUintType, false) })
	estimateTests(t, "ScalarAdd", func(fheUintType FheUintType) { FheAdd(t, fheUintType, true) })

	estimateTests(t, "sub", func(fheUintType FheUintType) { FheSub(t, fheUintType, false) })
	estimateTests(t, "ScalarSub", func(fheUintType FheUintType) { FheSub(t, fheUintType, true) })

	estimateTests(t, "mul", func(fheUintType FheUintType) { FheMul(t, fheUintType, false) })
	estimateTests(t, "ScalarMul", func(fheUintType FheUintType) { FheMul(t, fheUintType, true) })

	estimateTests(t, "ScalarDiv", func(fheUintType FheUintType) { FheDiv(t, fheUintType, true) })

	estimateTests(t, "IfThenElse", func(fheUintType FheUintType) { FheIfThenElse(t, fheUintType, 1) })
}
