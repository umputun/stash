package stash

//go:generate go run github.com/go-pkgz/enum@latest -type format -lower
type format int

const (
	formatText format = iota
	formatJSON
	formatYAML
	formatXML
	formatTOML
	formatINI
	formatHCL
	formatShell
)
