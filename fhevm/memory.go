// BSD 3-Clause Clear License

// Copyright © 2023 ZAMA.
// All rights reserved.

// Copyright 2015 The go-ethereum Authors
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

import "github.com/holiman/uint256"

type Memory interface {
	Set(offset, size uint64, value []byte)
	Set32(offset uint64, val *uint256.Int)
	Resize(size uint64)
	GetCopy(offset, size int64) (cpy []byte)
	GetPtr(offset, size int64) []byte
	Len() int
	Data() []byte
}
