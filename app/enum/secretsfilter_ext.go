package enum

// Next returns the next secrets filter in the cycle: all -> secrets -> keys -> all.
func (s SecretsFilter) Next() SecretsFilter {
	return SecretsFilterValues[(s.Index()+1)%len(SecretsFilterValues)]
}

// Label returns a user-friendly label for the filter.
func (s SecretsFilter) Label() string {
	switch s {
	case SecretsFilterSecretsOnly:
		return "Secrets"
	case SecretsFilterKeysOnly:
		return "Keys"
	default:
		return "All"
	}
}
