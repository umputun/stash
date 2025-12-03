package enum

// Next returns the next sort mode in the cycle: updated -> key -> size -> created -> updated.
func (s SortMode) Next() SortMode {
	return SortModeValues[(s.Index()+1)%len(SortModeValues)]
}
