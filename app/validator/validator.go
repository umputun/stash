// Package validator provides validation for known data formats.
package validator

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/hashicorp/hcl/v2/hclparse"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

// supportedFormats lists all supported value formats.
var supportedFormats = []string{"text", "json", "yaml", "xml", "toml", "ini", "hcl", "shell"}

// Service provides format validation for known data formats.
type Service struct{}

// NewService creates a new validation service.
func NewService() *Service {
	return &Service{}
}

// SupportedFormats returns the list of supported formats.
func (s *Service) SupportedFormats() []string {
	return supportedFormats
}

// IsValidFormat checks if format is in the list of supported formats.
func (s *Service) IsValidFormat(format string) bool {
	return slices.Contains(supportedFormats, format)
}

// Validate checks if value is valid for the given format.
// Returns nil for text, shell, or unknown formats (no validation).
// Returns descriptive error for invalid json, yaml, xml, toml, ini, hcl.
func (s *Service) Validate(format string, value []byte) error {
	switch format {
	case "json":
		return s.validateJSON(value)
	case "yaml":
		return s.validateYAML(value)
	case "xml":
		return s.validateXML(value)
	case "toml":
		return s.validateTOML(value)
	case "ini":
		return s.validateINI(value)
	case "hcl":
		return s.validateHCL(value)
	default:
		// text, shell, unknown formats - no validation
		return nil
	}
}

func (s *Service) validateJSON(value []byte) error {
	var v any
	if err := json.Unmarshal(value, &v); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func (s *Service) validateYAML(value []byte) error {
	var v any
	if err := yaml.Unmarshal(value, &v); err != nil {
		return fmt.Errorf("invalid yaml: %w", err)
	}
	return nil
}

func (s *Service) validateXML(value []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(value))
	hasElement := false
	for {
		tok, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("invalid xml: %w", err)
		}
		if _, ok := tok.(xml.StartElement); ok {
			hasElement = true
		}
	}
	if !hasElement {
		return errors.New("invalid xml: no root element found")
	}
	return nil
}

func (s *Service) validateTOML(value []byte) error {
	var v any
	if err := toml.Unmarshal(value, &v); err != nil {
		return fmt.Errorf("invalid toml: %w", err)
	}
	return nil
}

func (s *Service) validateINI(value []byte) error {
	_, err := ini.Load(value)
	if err != nil {
		return fmt.Errorf("invalid ini: %w", err)
	}
	return nil
}

func (s *Service) validateHCL(value []byte) error {
	parser := hclparse.NewParser()
	_, diags := parser.ParseHCL(value, "value.hcl")
	if diags.HasErrors() {
		return fmt.Errorf("invalid hcl: %s", diags.Error())
	}
	return nil
}
