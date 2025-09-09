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
	// "sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBufferPoolGetSize(t *testing.T) {
	const sz = 8 * 1024
	p := newBufferPool(sz)
	require.NotNil(t, p)

	buf := p.Get()
	require.Len(t, buf, sz)
	require.Equal(t, sz, cap(buf))
	p.Put(buf)
}

// func TestBufferReuse(t *testing.T) {
// 	const sz = 4096
// 	p := newBufferPool(sz)

// 	buf := p.Get()
// 	require.Len(t, buf, sz)
// 	buf[0] = 0xAB
// 	ptr1 := &buf[0]
// 	p.Put(buf)

// 	buf2 := p.Get()
// 	require.Len(t, buf2, sz)
// 	ptr2 := &buf2[0]

// 	// Likely the same underlying slice (reuse); if this ever fails it just means
// 	// implementation changed, not necessarily a functional problem.
// 	assert.Equal(t, ptr1, ptr2, "expected buffer to be reused from pool")
// 	assert.Equal(t, byte(0xAB), buf2[0], "pooled slice contents preserved (acceptable)")

// 	p.Put(buf2)
// }

func TestLargeBufferNotRetained(t *testing.T) {
	const sz = 2048
	p := newBufferPool(sz)

	huge := make([]byte, maxBufferSize+1024)
	p.Put(huge)

	buf := p.Get()
	require.Len(t, buf, sz)
	require.Equal(t, sz, cap(buf))
	p.Put(buf)
}

// func TestConcurrentGetPut(t *testing.T) {
// 	const (
// 		sz    = 1024
// 		goros = 32
// 		iters = 200
// 	)

// 	p := newBufferPool(sz)
// 	var wg sync.WaitGroup
// 	wg.Add(goros)

// 	for range goros {
// 		go func() {
// 			defer wg.Done()
// 			for range iters {
// 				b := p.Get()
// 				if len(b) != sz || cap(b) != sz {
// 					t.Errorf("unexpected buffer size len=%d cap=%d", len(b), cap(b))
// 				}
// 				p.Put(b)
// 			}
// 		}()
// 	}

// 	wg.Wait()
// }
