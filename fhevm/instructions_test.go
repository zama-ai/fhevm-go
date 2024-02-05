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
	"bytes"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/crypto"
)

func init() {
	// register errors from geth so that tests recognize them
	RegisterErrors(
		vm.ErrOutOfGas,
		vm.ErrCodeStoreOutOfGas,
		vm.ErrDepth,
		vm.ErrInsufficientBalance,
		vm.ErrContractAddressCollision,
		vm.ErrExecutionReverted,
		vm.ErrMaxInitCodeSizeExceeded,
		vm.ErrMaxCodeSizeExceeded,
		vm.ErrInvalidJump,
		vm.ErrWriteProtection,
		vm.ErrReturnDataOutOfBounds,
		vm.ErrGasUintOverflow,
		vm.ErrInvalidCode,
		vm.ErrNonceUintOverflow,
		nil,
		nil,
		nil,
	)
}

func verifyCiphertextInTestMemory(environment EVMEnvironment, value uint64, depth int, t FheUintType) *tfheCiphertext {
	// Simulate as if the ciphertext is compact and comes externally.
	ser := encryptAndSerializeCompact(uint64(value), t)
	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(ser, t)
	if err != nil {
		panic(err)
	}
	return verifyTfheCiphertextInTestMemory(environment, ct, depth)
}

func verifyTfheCiphertextInTestMemory(environment EVMEnvironment, ct *tfheCiphertext, depth int) *tfheCiphertext {
	verifiedCiphertext := importCiphertextToEVMAtDepth(environment, ct, depth)
	return verifiedCiphertext.ciphertext
}

// Implementation of some geth data structures used for testing

var stackPool = sync.Pool{
	New: func() interface{} {
		return &TestStack{data: make([]uint256.Int, 0, 16)}
	},
}

type TestStack struct {
	data []uint256.Int
}

func newstack() *TestStack {
	return stackPool.Get().(*TestStack)
}

// Data returns the underlying uint256.Int array.
func (st *TestStack) Data() []uint256.Int {
	return st.data
}

func (st *TestStack) push(d *uint256.Int) {
	// NOTE push limit (1024) is checked in baseCheck
	st.data = append(st.data, *d)
}

func (st *TestStack) pop() (ret uint256.Int) {
	ret = st.data[len(st.data)-1]
	st.data = st.data[:len(st.data)-1]
	return
}

func (st *TestStack) len() int {
	return len(st.data)
}

func (st *TestStack) peek() *uint256.Int {
	return &st.data[st.len()-1]
}

// Back returns the n'th item in stack
func (st *TestStack) Back(n int) *uint256.Int {
	return &st.data[st.len()-n-1]
}

func (st *TestStack) Peek() *uint256.Int { return st.peek() }

func (st *TestStack) Pop() uint256.Int { return st.pop() }

type TestScopeContext struct {
	Memory   *vm.Memory
	Stack    *TestStack
	Contract *vm.Contract
}

type TestScopeContextInterface interface {
	ScopeContext
	pushToStack(*uint256.Int)
}

func (scope *TestScopeContext) GetContract() Contract      { return scope.Contract }
func (scope *TestScopeContext) GetMemory() Memory          { return scope.Memory }
func (scope *TestScopeContext) GetStack() Stack            { return scope.Stack }
func (scope *TestScopeContext) pushToStack(v *uint256.Int) { scope.Stack.push(v) }

type testContractAddress struct{}

func (c testContractAddress) Address() common.Address {
	return common.Address{}
}

type testCallerAddress struct{}

func (c testCallerAddress) Address() common.Address {
	addr := common.Address{}
	addr[0]++
	return addr
}

func newTestScopeConext() TestScopeContextInterface {
	c := new(TestScopeContext)
	c.Memory = vm.NewMemory()
	c.Memory.Resize(uint64(expandedFheCiphertextSize[FheUint8]) * 3)
	c.Stack = newstack()
	c.Contract = vm.NewContract(testCallerAddress{}, testContractAddress{}, big.NewInt(10), 100000)
	return c
}

func uint256FromBig(b *big.Int) *uint256.Int {
	value, overflow := uint256.FromBig(b)
	if overflow {
		panic("overflow")
	}
	return value
}

type MockEVMEnvironment struct {
	fhevmData   *FhevmData
	depth       int
	stateDb     *state.StateDB
	commit      bool
	ethCall     bool
	readOnly    bool
	fhevmParams FhevmParams
}

func (environment *MockEVMEnvironment) GetState(addr common.Address, hash common.Hash) common.Hash {
	return environment.stateDb.GetState(addr, hash)
}

func (environment *MockEVMEnvironment) SetState(addr common.Address, key common.Hash, value common.Hash) {
	environment.stateDb.SetState(addr, key, value)
}

func (environment *MockEVMEnvironment) GetNonce(common.Address) uint64 {
	return 0
}

func (environment *MockEVMEnvironment) AddBalance(addr common.Address, amount *big.Int) {
	environment.stateDb.AddBalance(addr, amount)
}

func (environment *MockEVMEnvironment) GetBalance(addr common.Address) *big.Int {
	return environment.stateDb.GetBalance(addr)
}

func (environment *MockEVMEnvironment) Suicide(addr common.Address) bool {
	return environment.stateDb.Suicide(addr)
}

func (environment *MockEVMEnvironment) GetDepth() int {
	return environment.depth
}

func (environment *MockEVMEnvironment) GetLogger() Logger {
	return &DefaultLogger{}
}

func (environment *MockEVMEnvironment) IsCommitting() bool {
	return environment.commit
}

func (environment *MockEVMEnvironment) IsEthCall() bool {
	return environment.ethCall
}

func (environment *MockEVMEnvironment) IsReadOnly() bool {
	return environment.readOnly
}

func (environment *MockEVMEnvironment) CreateContract(caller common.Address, code []byte, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	return make([]byte, 0), common.Address{}, 0, nil
}

func (environment *MockEVMEnvironment) CreateContract2(caller common.Address, code []byte, codeHash common.Hash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	return make([]byte, 0), common.Address{}, 0, nil
}

func (environment *MockEVMEnvironment) FhevmData() *FhevmData {
	return environment.fhevmData
}

func (environment *MockEVMEnvironment) FhevmParams() *FhevmParams {
	return &environment.fhevmParams
}

func (environment *MockEVMEnvironment) EVMEnvironment() EVMEnvironment {
	return environment
}

func newTestEVMEnvironment() *MockEVMEnvironment {
	fhevmData := NewFhevmData()
	db := rawdb.NewMemoryDatabase()
	state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	return &MockEVMEnvironment{fhevmData: &fhevmData, stateDb: state, commit: true, fhevmParams: DefaultFhevmParams()}
}

func TestProtectedStorageSstoreSload(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 1
	environment.depth = depth
	ct := verifyCiphertextInTestMemory(environment, 2, depth, FheUint32)
	ctHash := ct.getHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256FromBig(ctHash.Big())

	// Setup and call SSTORE - it requires a location and a value to set there.
	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Clear the verified ciphertexts.
	environment.FhevmData().verifiedCiphertexts = make(map[common.Hash]*verifiedCiphertext)

	// Setup and call SLOAD - it requires a location to load.
	scope.pushToStack(loc)
	_, err = OpSload(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Expect the ciphertext is verified after SLOAD.
	ctAfterSload := getVerifiedCiphertextFromEVM(environment, ctHash)
	if ctAfterSload == nil {
		t.Fatalf("expected ciphertext is verified after sload")
	}
	if !bytes.Equal(ct.serialize(), ctAfterSload.ciphertext.serialize()) {
		t.Fatalf("expected ciphertext after sload is the same as original")
	}
}

func TestProtectedStorageGarbageCollectionNoFlaggedLocation(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 1
	environment.depth = depth
	ctHash := verifyCiphertextInTestMemory(environment, 2, depth, FheUint8).getHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	locHash := common.BytesToHash(loc.Bytes())
	value := uint256FromBig(ctHash.Big())
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(scope.GetContract().Address())

	// Persist the ciphertext in protected storage.
	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Set location flag to zero, such that garbage collection doesn't happen.
	flagHandleLocation := crypto.Keccak256Hash(crypto.Keccak256Hash(locHash.Bytes()).Bytes())
	environment.SetState(protectedStorage, flagHandleLocation, zero)

	// Overwrite the ciphertext handle with 0.
	scope.pushToStack(uint256.NewInt(0))
	scope.pushToStack(loc)
	_, err = OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Verify that garbage collection hasn't happened.
	metadata := ciphertextMetadata{}
	metadataKey := crypto.Keccak256Hash(ctHash.Bytes())
	metadata.deserialize(environment.GetState(protectedStorage, metadataKey))
	slot := uint256FromBig(metadataKey.Big())
	slot = slot.AddUint64(slot, 1)
	foundNonZero := false
	for i := uint64(0); i < metadata.length; i++ {
		res := environment.GetState(protectedStorage, common.BytesToHash(slot.Bytes()))
		if !bytes.Equal(res.Bytes(), zero.Bytes()) {
			foundNonZero = true
			break
		}
		slot = slot.AddUint64(slot, i)
	}
	if !foundNonZero {
		t.Fatalf("garbage collection must not have happened")
	}
}

func TestProtectedStorageGarbageCollection(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 1
	environment.depth = depth
	ctHash := verifyCiphertextInTestMemory(environment, 2, depth, FheUint8).getHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	locHash := common.BytesToHash(loc.Bytes())
	value := uint256FromBig(ctHash.Big())

	// Persist the ciphertext in protected storage.
	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Make sure ciphertext is persisted to protected storage.
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(scope.GetContract().Address())
	metadata := ciphertextMetadata{}
	metadataKey := crypto.Keccak256Hash(ctHash.Bytes())
	metadata.deserialize(environment.GetState(protectedStorage, metadataKey))
	if metadata.refCount != 1 {
		t.Fatalf("metadata.refcount of ciphertext is not 1")
	}
	if metadata.length != uint64(expandedFheCiphertextSize[FheUint8]) {
		t.Fatalf("metadata.length (%v) != ciphertext len (%v)", metadata.length, uint64(expandedFheCiphertextSize[FheUint8]))
	}
	ciphertextLocationsToCheck := (metadata.length + 32 - 1) / 32
	startOfCiphertext := newInt(metadataKey.Bytes())
	startOfCiphertext.AddUint64(startOfCiphertext, 1)
	ctIdx := startOfCiphertext
	foundNonZero := false
	for i := uint64(0); i < ciphertextLocationsToCheck; i++ {
		c := environment.GetState(protectedStorage, common.BytesToHash(ctIdx.Bytes()))
		u := uint256FromBig(c.Big())
		if !u.IsZero() {
			foundNonZero = true
			break
		}
		ctIdx.AddUint64(startOfCiphertext, 1)
	}
	if !foundNonZero {
		t.Fatalf("ciphertext is not persisted to protected storage")
	}

	// Check if the handle location is flagged in protected storage.
	flagHandleLocation := crypto.Keccak256Hash(crypto.Keccak256Hash(locHash.Bytes()).Bytes())
	foundFlag := environment.GetState(protectedStorage, flagHandleLocation)
	if !bytes.Equal(foundFlag.Bytes(), flag.Bytes()) {
		t.Fatalf("location flag not persisted to protected storage")
	}

	// Overwrite the ciphertext handle with 0.
	scope.pushToStack(uint256.NewInt(0))
	scope.pushToStack(loc)
	_, err = OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Make sure the metadata and the ciphertext are garbage collected from protected storage.
	protectedStorageIdx := newInt(metadataKey.Bytes())
	foundNonZero = false
	for i := uint64(0); i < ciphertextLocationsToCheck; i++ {
		c := environment.GetState(protectedStorage, common.BytesToHash(protectedStorageIdx.Bytes()))
		u := uint256FromBig(c.Big())
		if !u.IsZero() {
			foundNonZero = true
			break
		}
		ctIdx.AddUint64(startOfCiphertext, 1)
	}
	if foundNonZero {
		t.Fatalf("ciphertext is not garbage collected from protected storage")
	}

	// Make sure the flag location is zero.
	foundFlag = environment.GetState(protectedStorage, flagHandleLocation)
	if !bytes.Equal(foundFlag.Bytes(), zero.Bytes()) {
		t.Fatalf("location flag is not set to zero on garbage collection")
	}
}

func TestProtectedStorageSloadDoesNotVerifyNonHandle(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256.NewInt(42)

	scope.pushToStack(value)
	scope.pushToStack(loc)
	_, err := OpSstore(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	scope.pushToStack(loc)
	_, err = OpSload(&pc, environment, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Expect no verified ciphertexts.
	if len(environment.FhevmData().verifiedCiphertexts) != 0 {
		t.Fatalf("expected no verified ciphetexts")
	}
}

func TestOpReturnDelegation(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 2
	scope := newTestScopeConext()
	ct := verifyCiphertextInTestMemory(environment, 2, depth, FheUint8)
	ctHash := ct.getHash()

	offset := uint256.NewInt(0)
	length := uint256.NewInt(32)
	scope.pushToStack(length)
	scope.pushToStack(offset)
	scope.GetMemory().Set(offset.Uint64(), length.Uint64(), ctHash[:])
	environment.depth = depth
	OpReturn(&pc, environment, scope)
	environment.depth--
	ctAfterOp := getVerifiedCiphertextFromEVM(environment, ctHash)
	if ctAfterOp == nil {
		t.Fatalf("expected ciphertext is still verified after the return op")
	}
	if !bytes.Equal(ct.serialize(), ctAfterOp.ciphertext.serialize()) {
		t.Fatalf("expected ciphertext after the return op is the same as original")
	}
}

func TestOpReturnUnverifyIfNotReturned(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	depth := 2
	scope := newTestScopeConext()
	ctHash := verifyCiphertextInTestMemory(environment, 2, depth, FheUint8).getHash()

	offset := uint256.NewInt(0)
	len := uint256.NewInt(32)
	scope.pushToStack(len)
	scope.pushToStack(offset)
	// Set 0s as return.
	scope.GetMemory().Set(offset.Uint64(), len.Uint64(), make([]byte, len.Uint64()))
	environment.depth = depth
	OpReturn(&pc, environment, scope)
	environment.depth = depth - 1
	ct := getVerifiedCiphertextFromEVM(environment, ctHash)
	if ct != nil {
		t.Fatalf("expected ciphertext is not verified after the return op")
	}
}

func TestOpReturnDoesNotUnverifyIfNotVerified(t *testing.T) {
	environment := newTestEVMEnvironment()
	pc := uint64(0)
	scope := newTestScopeConext()
	ct := verifyCiphertextInTestMemory(environment, 2, 4, FheUint8)
	ctHash := ct.getHash()

	// Return from depth 3 to depth 2. However, ct is not verified at 3 and, hence, cannot
	// be passed from 3 to 2. However, we expect that ct remains verified at 4.
	offset := uint256.NewInt(0)
	len := uint256.NewInt(32)
	scope.pushToStack(len)
	scope.pushToStack(offset)
	scope.GetMemory().Set(offset.Uint64(), len.Uint64(), ctHash[:])
	environment.depth = 3
	OpReturn(&pc, environment, scope)
	environment.depth--

	ctAt2 := getVerifiedCiphertextFromEVM(environment, ctHash)
	if ctAt2 != nil {
		t.Fatalf("expected ciphertext is not verified at 2")
	}
	environment.depth = 3
	ctAt3 := getVerifiedCiphertextFromEVM(environment, ctHash)
	if ctAt3 != nil {
		t.Fatalf("expected ciphertext is not verified at 3")
	}
	environment.depth = 4
	ctAt4 := getVerifiedCiphertextFromEVM(environment, ctHash)
	if ctAt4 == nil {
		t.Fatalf("expected ciphertext is still verified at 4")
	}
	if !bytes.Equal(ct.serialize(), ctAt4.ciphertext.serialize()) {
		t.Fatalf("expected ciphertext after the return op is the same as original")
	}
	if ctAt4.verifiedDepths.count() != 1 || !ctAt4.verifiedDepths.has(environment.depth) {
		t.Fatalf("expected ciphertext to be verified at depth 4")
	}
}
