package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/invopop/jsonschema"

	"github.com/umputun/stash/app/server"
)

func main() {
	schema := jsonschema.Reflect(&server.AuthConfig{})
	schema.Title = "Stash Auth Configuration"

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal schema: %v", err)
	}

	outputPath := "schema.json"
	if len(os.Args) > 1 {
		outputPath = os.Args[1]
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil { //nolint:gosec // schema file is not sensitive
		log.Fatalf("failed to write schema file: %v", err)
	}
}
