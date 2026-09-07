package enum

// CanRead returns true if the permission allows reading. Write permission implies read:
// the UI edit and conflict flows return the current value to anyone allowed to write it.
func (p Permission) CanRead() bool {
	return p == PermissionRead || p == PermissionWrite || p == PermissionReadWrite
}

// CanWrite returns true if the permission allows writing.
func (p Permission) CanWrite() bool {
	return p == PermissionWrite || p == PermissionReadWrite
}
