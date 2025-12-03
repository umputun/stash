package enum

// ContentType returns the HTTP Content-Type for the format.
func (f Format) ContentType() string {
	switch f {
	case FormatJSON:
		return "application/json"
	case FormatYAML:
		return "application/yaml"
	case FormatXML:
		return "application/xml"
	case FormatTOML:
		return "application/toml"
	case FormatShell:
		return "text/x-shellscript"
	default: // text, ini, hcl
		return "text/plain"
	}
}
