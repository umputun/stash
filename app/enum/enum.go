package enum

//go:generate go run github.com/go-pkgz/enum@latest -type permission -lower
type permission int

const (
	permissionNone      permission = iota // enum:alias=none
	permissionRead                        // enum:alias=r
	permissionWrite                       // enum:alias=w
	permissionReadWrite                   // enum:alias=rw,read-write
)

//go:generate go run github.com/go-pkgz/enum@latest -type dbType -lower
type dbType int

const (
	dbTypeSQLite   dbType = iota // enum:alias=sqlite
	dbTypePostgres               // enum:alias=postgres
)

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

//go:generate go run github.com/go-pkgz/enum@latest -type viewMode -lower
type viewMode int

const (
	viewModeGrid viewMode = iota
	viewModeCards
)

//go:generate go run github.com/go-pkgz/enum@latest -type sortMode -lower
type sortMode int

const (
	sortModeUpdated sortMode = iota
	sortModeKey
	sortModeSize
	sortModeCreated
)

//go:generate go run github.com/go-pkgz/enum@latest -type theme -lower
type theme int

const (
	themeSystem theme = iota // enum:alias=
	themeLight
	themeDark
)
