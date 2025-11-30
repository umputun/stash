package server

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/invopop/jsonschema"
	validator "github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

//go:embed schema.json
var embeddedSchemaData []byte

// GenerateAuthSchema generates JSON schema for AuthConfig struct.
func GenerateAuthSchema() ([]byte, error) {
	schema := jsonschema.Reflect(&AuthConfig{})
	schema.Title = "Stash Auth Configuration"
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema: %w", err)
	}
	return data, nil
}

// VerifyAuthConfig validates auth config data against the embedded JSON schema.
func VerifyAuthConfig(data []byte) error {
	if len(embeddedSchemaData) == 0 {
		return errors.New("embedded auth schema is empty")
	}

	// compile the embedded schema
	compiler := validator.NewCompiler()
	if err := compiler.AddResource("schema.json", bytes.NewReader(embeddedSchemaData)); err != nil {
		return fmt.Errorf("failed to add schema resource: %w", err)
	}

	schema, err := compiler.Compile("schema.json")
	if err != nil {
		return fmt.Errorf("failed to compile schema: %w", err)
	}

	// parse yaml config into generic map for schema validation
	var cfg any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse auth config file: %w", err)
	}

	// validate against schema
	if err := schema.Validate(cfg); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	return nil
}
