package server

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

//go:embed schema.json
var embeddedSchemaData []byte

// VerifyAuthConfig validates auth config data against the embedded JSON schema.
func VerifyAuthConfig(data []byte) error {
	if len(embeddedSchemaData) == 0 {
		return fmt.Errorf("embedded auth schema is empty")
	}

	// compile the embedded schema
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("schema.json", bytes.NewReader(embeddedSchemaData)); err != nil {
		return fmt.Errorf("failed to add schema resource: %w", err)
	}

	schema, err := compiler.Compile("schema.json")
	if err != nil {
		return fmt.Errorf("failed to compile schema: %w", err)
	}

	// parse yaml config into generic map for schema validation
	var cfg interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse auth config file: %w", err)
	}

	// validate against schema
	if err := schema.Validate(cfg); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	return nil
}
