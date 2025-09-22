package util

import (
	"fmt"
)

// Conv attempts to cast the given value to type T.
func Conv[T any](v any) (T, error) {
	vt, ok := v.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("expected %T, got %T", zero, v)
	}
	return vt, nil
}

// Keys returns the keys of the given map as a slice.
func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// DB extracts the database name as the first segment of the
// given CouchDB URL path. It returns an empty string if the path
// is empty, does not start with a slash, or does not have a segment.
func DB(path string) string {
	if path == "" || path[0] != '/' {
		return ""
	}
	i := 1
	for j := i; j < len(path); j++ {
		if path[j] == '/' {
			return path[i:j]
		}
	}
	// Database names are URL-safe; decoding is not needed.
	return path[i:]
}
