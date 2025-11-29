package main

import (
	"log"
	"os"

	"github.com/umputun/stash/app/server"
)

func main() {
	data, err := server.GenerateAuthSchema()
	if err != nil {
		log.Fatalf("failed to generate schema: %v", err)
	}

	outputPath := "schema.json"
	if len(os.Args) > 1 {
		outputPath = os.Args[1]
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil { //nolint:gosec // schema file is not sensitive
		log.Fatalf("failed to write schema file: %v", err)
	}
}
