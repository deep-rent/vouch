// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"net/http/httputil"
	"sync"
)

// MaxBufferSize is the maximum buffer size to keep in the pool.
const MaxBufferSize int = 256 << 10 // 256 KiB

// BufferPool implements httputil.BufferPool backed by sync.Pool.
// It reduces allocations for large response bodies by reusing byte slices,
// thus lowering GC pressure.
type BufferPool struct{ pool sync.Pool }

// NewBufferPool creates a buffer pool that returns buffers of at least size
// bytes. Buffers larger than 256 KiB are not kept to avoid memory bloat.
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				// Store a pointer to a slice to avoid allocations when storing in the
				// interface-typed pool.
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

// Get returns a reusable buffer slice.
func (b *BufferPool) Get() []byte {
	//nolint:errcheck // guaranteed to be *[]byte
	return *b.pool.Get().(*[]byte)
}

// Put returns the buffer to the pool unless it grew beyond the size limit.
func (b *BufferPool) Put(buf []byte) {
	if cap(buf) <= MaxBufferSize { // Avoid holding on to very large buffers.
		b.pool.Put(&buf)
	}
}

// Ensure bufferPool satisfies the interface expected by httputil.ReverseProxy.
var _ httputil.BufferPool = (*BufferPool)(nil)
