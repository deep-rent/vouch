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

package auth

import "testing"

func TestDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "root only", in: "/", want: ""},
		{name: "no leading slash", in: "db", want: "db"},
		{name: "single segment", in: "/db", want: "db"},
		{name: "with trailing slash", in: "/db/", want: "db"},
		{name: "with extra path", in: "/db/_all_docs", want: "db"},
		{name: "percent-escaped slash", in: "/my%2Fdb", want: "my/db"},
		{name: "percent-escaped slash + extra", in: "/db%2F1/_all_docs", want: "db/1"},
		{name: "invalid percent escape", in: "/db%ZZ", want: "db%ZZ"},
		{name: "unicode plain", in: "/café", want: "café"},
		{name: "unicode percent-escaped", in: "/caf%C3%A9", want: "café"},
		{name: "no leading slash percent-escaped", in: "my%2Fdb", want: "my/db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Database(tt.in)
			if got != tt.want {
				t.Fatalf("Database(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
