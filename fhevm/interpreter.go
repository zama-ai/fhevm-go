package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

type ScopeContext interface {
	GetMemory() Memory
	GetStack() Stack
	GetContract() Contract
}

type depthSet struct {
	m map[int]struct{}
}

func newDepthSet() *depthSet {
	s := &depthSet{}
	s.m = make(map[int]struct{})
	return s
}

func (s *depthSet) add(v int) {
	s.m[v] = struct{}{}
}

func (s *depthSet) del(v int) {
	delete(s.m, v)
}

func (s *depthSet) has(v int) bool {
	_, found := s.m[v]
	return found
}

func (s *depthSet) count() int {
	return len(s.m)
}

func (from *depthSet) clone() (to *depthSet) {
	to = newDepthSet()
	for k := range from.m {
		to.add(k)
	}
	return
}

type verifiedCiphertext struct {
	verifiedDepths *depthSet
	ciphertext     *tfheCiphertext
}

type PrivilegedMemory struct {
	// A map from a ciphertext hash to itself and stack depths at which it is verified
	VerifiedCiphertexts map[common.Hash]*verifiedCiphertext

	// All optimistic requires encountered up to that point in the txn execution
	OptimisticRequires []*tfheCiphertext
}

var PrivilegedMempory *PrivilegedMemory = &PrivilegedMemory{
	make(map[common.Hash]*verifiedCiphertext),
	make([]*tfheCiphertext, 0),
}

// Evaluate remaining optimistic requires when Interpreter.Run get an errStopToken
//
// This function is meant to be integrated as part of vm.EVMInterpreter.Run in the case
// there was an errStopToken
func EvalRemOptReqWhenStopToken(env EVMEnvironment, depth int) (err error) {
	// If we are finishing execution (about to go to from depth 1 to depth 0), evaluate
	// any remaining optimistic requires.
	if depth == 1 {
		result, evalErr := evaluateRemainingOptimisticRequires(env)
		if evalErr != nil {
			return evalErr
		} else if !result {
			return ErrExecutionReverted
		}
	}
	return nil
}

// Function meant to be run instead of vm.EVMInterpreter.Run inside an fhEVM
//
// It makes sure to remove ciphertexts used at current depth during interpreter execution, but also evaluate remaining optimistic requires if necessary
func InterpreterRun(environment EVMEnvironment, interpreter *vm.EVMInterpreter, contract *vm.Contract, input []byte, readOnly bool) (ret []byte, err error) {
	ret, err = interpreter.Run(contract, input, readOnly)
	// the following functions are meant to be ran from within interpreter.Run so we increment depth to emulate that
	depth := environment.GetDepth() + 1
	RemoveVerifiedCipherextsAtCurrentDepth(environment, depth)
	// if contract is not empty and err is nil, then an errStopToken was cleared inside interpreter.Run
	if len(contract.Code) != 0 && err == nil {
		err = EvalRemOptReqWhenStopToken(environment, depth)
		return ret, err
	}
	return ret, err
}
