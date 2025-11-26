package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_Validate(t *testing.T) {
	svc := NewService()

	tests := []struct {
		name    string
		format  string
		value   []byte
		wantErr bool
	}{
		// json tests
		{name: "valid json object", format: "json", value: []byte(`{"key": "value"}`), wantErr: false},
		{name: "valid json array", format: "json", value: []byte(`[1, 2, 3]`), wantErr: false},
		{name: "valid json string", format: "json", value: []byte(`"hello"`), wantErr: false},
		{name: "valid json number", format: "json", value: []byte(`123`), wantErr: false},
		{name: "valid json boolean", format: "json", value: []byte(`true`), wantErr: false},
		{name: "valid json null", format: "json", value: []byte(`null`), wantErr: false},
		{name: "invalid json missing quote", format: "json", value: []byte(`{"key: "value"}`), wantErr: true},
		{name: "invalid json trailing comma", format: "json", value: []byte(`{"key": "value",}`), wantErr: true},
		{name: "invalid json unclosed brace", format: "json", value: []byte(`{"key": "value"`), wantErr: true},

		// yaml tests
		{name: "valid yaml simple", format: "yaml", value: []byte("key: value"), wantErr: false},
		{name: "valid yaml nested", format: "yaml", value: []byte("parent:\n  child: value"), wantErr: false},
		{name: "valid yaml list", format: "yaml", value: []byte("- item1\n- item2"), wantErr: false},
		{name: "invalid yaml duplicate key mapping", format: "yaml", value: []byte("a: 1\na: 2: 3"), wantErr: true},
		{name: "invalid yaml tab indent", format: "yaml", value: []byte("key:\n\tvalue"), wantErr: true},

		// xml tests
		{name: "valid xml simple", format: "xml", value: []byte(`<root>content</root>`), wantErr: false},
		{name: "valid xml nested", format: "xml", value: []byte(`<root><child>value</child></root>`), wantErr: false},
		{name: "valid xml with attributes", format: "xml", value: []byte(`<root attr="val">content</root>`), wantErr: false},
		{name: "invalid xml unclosed tag", format: "xml", value: []byte(`<root>content`), wantErr: true},
		{name: "invalid xml mismatched tags", format: "xml", value: []byte(`<root>content</other>`), wantErr: true},

		// toml tests
		{name: "valid toml simple", format: "toml", value: []byte(`key = "value"`), wantErr: false},
		{name: "valid toml section", format: "toml", value: []byte("[section]\nkey = \"value\""), wantErr: false},
		{name: "valid toml number", format: "toml", value: []byte(`port = 8080`), wantErr: false},
		{name: "invalid toml missing equals", format: "toml", value: []byte(`key "value"`), wantErr: true},
		{name: "invalid toml bad string", format: "toml", value: []byte(`key = "unclosed`), wantErr: true},

		// ini tests
		{name: "valid ini simple", format: "ini", value: []byte("key=value"), wantErr: false},
		{name: "valid ini with section", format: "ini", value: []byte("[section]\nkey=value"), wantErr: false},
		{name: "valid ini with spaces", format: "ini", value: []byte("key = value"), wantErr: false},
		{name: "valid ini comment", format: "ini", value: []byte("; comment\nkey=value"), wantErr: false},
		{name: "invalid ini no equals", format: "ini", value: []byte("[section]\nbadline"), wantErr: true},

		// hcl tests
		{name: "valid hcl simple", format: "hcl", value: []byte(`key = "value"`), wantErr: false},
		{name: "valid hcl block", format: "hcl", value: []byte("resource \"aws_instance\" \"example\" {\n  ami = \"ami-12345\"\n}"), wantErr: false},
		{name: "valid hcl nested", format: "hcl", value: []byte("server {\n  host = \"localhost\"\n  port = 8080\n}"), wantErr: false},
		{name: "invalid hcl unclosed brace", format: "hcl", value: []byte("server {\n  host = \"localhost\""), wantErr: true},
		{name: "invalid hcl bad syntax", format: "hcl", value: []byte("key value"), wantErr: true},

		// formats that skip validation
		{name: "text skips validation", format: "text", value: []byte("any content here {["), wantErr: false},
		{name: "shell skips validation", format: "shell", value: []byte("echo $VAR"), wantErr: false},
		{name: "unknown format skips validation", format: "unknown", value: []byte("anything"), wantErr: false},
		{name: "empty format skips validation", format: "", value: []byte("anything"), wantErr: false},

		// edge cases
		{name: "empty value json", format: "json", value: []byte{}, wantErr: true},
		{name: "empty value yaml", format: "yaml", value: []byte{}, wantErr: false},
		{name: "empty value text", format: "text", value: []byte{}, wantErr: false},
		{name: "whitespace only json", format: "json", value: []byte("   "), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.Validate(tt.format, tt.value)
			if tt.wantErr {
				assert.Error(t, err, "expected error for %s", tt.name)
			} else {
				assert.NoError(t, err, "expected no error for %s", tt.name)
			}
		})
	}
}

func TestService_Validate_ErrorMessages(t *testing.T) {
	svc := NewService()

	// verify error messages are descriptive
	tests := []struct {
		name        string
		format      string
		value       []byte
		errContains string
	}{
		{name: "json error contains format", format: "json", value: []byte(`{bad`), errContains: "json"},
		{name: "yaml error contains format", format: "yaml", value: []byte(":\n\tbad"), errContains: "yaml"},
		{name: "xml error contains format", format: "xml", value: []byte(`<unclosed`), errContains: "xml"},
		{name: "toml error contains format", format: "toml", value: []byte(`bad`), errContains: "toml"},
		{name: "ini error contains format", format: "ini", value: []byte("[section]\nbad"), errContains: "ini"},
		{name: "hcl error contains format", format: "hcl", value: []byte("bad {"), errContains: "hcl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.Validate(tt.format, tt.value)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}
