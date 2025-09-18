package proxy

import (
	"net/http/httputil"
	"sync"
)

// BufferPool implements httputil.BufferPool backed by sync.Pool.
// It reduces allocations for large response bodies by reusing byte slices,
// thus lowering GC pressure.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a BufferPool that returns buffers of at least m
// bytes. Buffers that grow beyond n will be discarded.
//
// Both parameters must be positive; m will be clamped by n.
func NewBufferPool(m int, n int) *BufferPool {
	if m <= 0 {
		panic("m must be positive")
	}
	if n <= 0 {
		panic("n must be positive")
	}
	m = min(m, n)
	// Store a pointer to a slice to avoid allocations when storing in the
	// interface-typed pool
	alloc := func() any {
		buf := make([]byte, m)
		return &buf
	}
	return &BufferPool{
		pool: sync.Pool{New: alloc},
		size: n,
	}
}

// Get returns a reusable buffer slice.
func (b *BufferPool) Get() []byte {
	//nolint:errcheck // guaranteed to be *[]byte
	return *b.pool.Get().(*[]byte)
}

// Put returns the buffer to the pool unless it grew beyond the size limit.
func (b *BufferPool) Put(buf []byte) {
	// Avoid holding on to overly large buffers
	if cap(buf) <= b.size {
		b.pool.Put(&buf)
	}
}

// Ensure bufferPool implements the httputil.BufferPool interface.
var _ httputil.BufferPool = (*BufferPool)(nil)
