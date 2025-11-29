package couch

import "strings"

func Database(path string) string {
	const start = 1
	if len(path) <= start {
		return ""
	}
	end := strings.IndexByte(path[start:], '/')
	if end == -1 {
		return path[start:]
	}
	return path[start:(start + end)]
}
