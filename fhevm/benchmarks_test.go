// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package fhevm

import (
	"testing"
	"time"
	"sync"
)

type operation func(FheUintType)

const numBenchmarkRuns = 10 

func convertInGas(t *testing.T, name string, elapsed [numBenchmarkRuns]time.Duration) {
	lowest := elapsed[0]

	// Find the lowest duration in the array
	for i := 1; i < numBenchmarkRuns; i++ {
		if elapsed[i] < lowest {
			lowest = elapsed[i]
		}
	}

	gasUsed := int64(lowest) / 1000 // 1s = 1,000,000 gas
	gasUsed = gasUsed / 7 * 10      // 1s = 100k
	gasUsed = gasUsed / 1000        // Divide to round it

	t.Logf("%s in %s => %d", name, lowest, gasUsed*1000)
}

func runTest(t *testing.T, name string, fn operation, bits string, fheUintType FheUintType, wg *sync.WaitGroup) {
	defer wg.Done()
	var elapsed [numBenchmarkRuns]time.Duration
	n := 0
	for n < numBenchmarkRuns {
		start := time.Now()
		fn(fheUintType)
  	elapsed[n] = time.Since(start)
		n += 1
	}
	convertInGas(t, name + bits, elapsed)
}

func benchTests(t *testing.T, name string, fn operation) {
	var wg sync.WaitGroup
	wg.Add(3)

	go runTest(t, name, fn, "8", FheUint8, &wg)
	go runTest(t, name, fn, "16", FheUint16, &wg)
	go runTest(t, name, fn, "32", FheUint32, &wg)

	wg.Wait()
}

func TestBenchmarks(t *testing.T) {
	benchTests(t, "add", func(fheUintType FheUintType) { FheAdd(t, fheUintType, false) })
	benchTests(t, "ScalarAdd", func(fheUintType FheUintType) { FheAdd(t, fheUintType, true) })

	benchTests(t, "sub", func(fheUintType FheUintType) { FheSub(t, fheUintType, false) })
	benchTests(t, "ScalarSub", func(fheUintType FheUintType) { FheSub(t, fheUintType, true) })

	benchTests(t, "mul", func(fheUintType FheUintType) { FheMul(t, fheUintType, false) })
	benchTests(t, "ScalarMul", func(fheUintType FheUintType) { FheMul(t, fheUintType, true) })

	benchTests(t, "ScalarDiv", func(fheUintType FheUintType) { FheDiv(t, fheUintType, true) })

	benchTests(t, "IfThenElse", func(fheUintType FheUintType) { FheIfThenElse(t, fheUintType, 1) })
}
