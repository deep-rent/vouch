package cache

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxAge extracts the 'max-age' directive from a Cache-Control header string.
// If valid, it returns the duration and true, false otherwise.
func MaxAge(v string) (time.Duration, bool) {
	if v != "" {
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

// Expires parses an HTTP Expires header value.
// If valid, it returns the timestamp and true, false otherwise.
func Expires(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
