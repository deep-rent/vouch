package cache

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ETag encapsulates the ETag and Last-Modified headers of an HTTP response.
// It is used by Cache to negotiate conditional requests.
type ETag struct {
	Value        string // optional
	LastModified string // optional
}

// NewETag creates an ETag from the given HTTP headers.
func NewETag(header http.Header) ETag {
	return ETag{
		Value:        header.Get("ETag"),
		LastModified: header.Get("Last-Modified"),
	}
}

// Set adds the If-None-Match and Last-Modified headers, if available, to the
// given header map.
func (e ETag) Set(header http.Header) {
	if e.Value != "" {
		header.Set("If-None-Match", e.Value)
	}
	if e.LastModified != "" {
		header.Set("If-Modified-Since", e.LastModified)
	}
}

// MaxAge extracts the 'max-age' directive from a Cache-Control header.
// If valid, it returns the duration and true, false otherwise.
func MaxAge(header http.Header) (time.Duration, bool) {
	v := header.Get("Cache-Control")
	if v != "" {
		// The header consists of comma-separated key-value pairs
		for p := range strings.SplitSeq(v, ",") {
			p = strings.TrimSpace(p)
			if s, ok := strings.CutPrefix(p, "max-age="); ok {
				if d, err := strconv.Atoi(s); err == nil && d > 0 {
					return time.Duration(d) * time.Second, true
				}
			}
		}
	}
	return 0, false
}

// Expires parses an HTTP Expires header.
// If valid, it returns the timestamp and true, false otherwise.
func Expires(header http.Header) (time.Time, bool) {
	v := header.Get("Expires")
	if v == "" {
		return time.Time{}, false
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
