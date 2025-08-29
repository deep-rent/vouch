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

package main

import (
	"context"
	"log"
	"net/http"

	plugin "github.com/deep-rent/traefik-plugin-couchdb"
	"github.com/deep-rent/traefik-plugin-couchdb/auth"
)

func main() {
	config := plugin.CreateConfig()
	config.JWKS = "https://auth.example.com/.well-known/jwks.json"
	config.Rules = []auth.Rule{
		{
			When: "true",
			Mode: "deny",
		},
	}

	h, err := plugin.New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), config, "local-test")
	if err != nil {
		log.Fatalf("constructor probe failed: %v", err)
	}
	_ = h
}
