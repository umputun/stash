package enum

// CanRead returns true if the permission allows reading.
func (p Permission) CanRead() bool {
	return p == PermissionRead || p == PermissionReadWrite
}

// CanWrite returns true if the permission allows writing.
func (p Permission) CanWrite() bool {
	return p == PermissionWrite || p == PermissionReadWrite
}
