# Changelog

All notable changes to this project are documented in this file.

## [0.11.0] - 2025-12-04

### Added
- Persistent session storage in database - sessions survive server restarts (#23)

### Changed
- Migrated manual enums to go-pkgz/enum for type-safe enum handling (#22)
- Added context.Context to all store methods
- Refactored paginate to return struct instead of multiple values

## [0.10.4] - 2025-12-02

### Fixed
- Removed border from cards container

## [0.10.3] - 2025-12-02

### Changed
- Improved table styling with cleaner header and distinct background color
- Reduced table row padding for more compact look
- Updated favicon colors to match primary color scheme

## [0.10.2] - 2025-12-01

### Changed
- Unified blue color scheme using CSS variables for consistency
- Increased default session TTL from 24h to 30 days

## [0.10.1] - 2025-11-30

### Changed
- Refactored code to use Go 1.22+ integer range syntax
- Eliminated else blocks using early returns and continue
- Simplified DB queries with extended adoptQuery
- Moved conflict detection from web handler to store layer
- Enhanced linter configuration with additional static analysis rules

### Fixed
- UI icons and modal/pagination issues

## [0.10.0] - 2025-11-29

### Added
- Auth config hot-reload support with fsnotify file watcher
- Automatic reload of users, tokens, and permissions when config file changes
- Session invalidation on config reload to enforce new permissions immediately
- `--auth.hot-reload` flag and `STASH_AUTH_HOT_RELOAD` environment variable

## [0.9.2] - 2025-11-29

### Added
- JSON schema validation for auth config files

### Fixed
- HTMX requests now handled correctly in session auth middleware

## [0.9.1] - 2025-11-28

### Changed
- Server package refactored into api/web subpackages for better organization
- Improved test coverage

## [0.9.0] - 2025-11-28

### Added
- `GET /kv/` API endpoint to list all keys with metadata
- Optional `?prefix=` query parameter for filtering keys
- Auth-aware key listing (results filtered by caller permissions)
- Pagination for web UI key lists
- `--server.page-size` flag for configurable page size

## [0.8.2] - 2025-11-28

### Added
- Conflict detection for concurrent key edits (optimistic locking)
- Autofocus on form fields

### Changed
- Web handlers split into focused files for maintainability
- Code duplication eliminated with generics

### Fixed
- Static file serving restricted to GET method only

## [0.8.1] - 2025-11-27

### Fixed
- Duplicate key creation in web UI now shows error instead of silently overwriting
- Button visibility in form validation error states

## [0.8.0] - 2025-11-27

### Added
- Optional in-memory cache for read operations using go-pkgz/lcw
- `--cache.enabled` and `--cache.max-keys` flags
- Automatic cache invalidation on write operations

### Changed
- Responsive design improvements for mobile screens
- Progressive column hiding on smaller viewports
- Card view opens modal on click anywhere

## [0.7.3] - 2025-11-26

### Added
- Format metadata stored in git commit messages
- Restore command preserves original format
- Configurable server timeouts (read/write/idle)
- Request rate limiting and body size limits

### Changed
- Key normalization across API and web handlers
- Quick start section added to README

## [0.7.2] - 2025-11-26

### Changed
- Improved audit logging for mutations and access denial

## [0.7.1] - 2025-11-26

### Changed
- API returns format-appropriate Content-Type headers
- Token prefix used for git author identification

## [0.7.0] - 2025-11-26

### Added
- Format validation for web forms (json, yaml, xml, toml, ini, hcl)
- HCL syntax highlighting support
- Save and Submit Anyway buttons for validation errors

### Fixed
- Consistent button heights in toolbar
- Binary values no longer show empty in view modal
- Softer danger color for dark theme readability

## [0.6.0] - 2025-11-26

### Added
- `--git.ssh-key` option for SSH key authentication on git push/pull
- `STASH_GIT_SSH_KEY` environment variable support

## [0.5.0] - 2025-11-26

### Added
- Public access support with `token: "*"` wildcard
- Unauthenticated access to specific key prefixes for public endpoints

## [0.4.0] - 2025-11-25

### Added
- Syntax highlighting for KV values in web UI
- Authenticated username used as git commit author

## [0.3.1] - 2025-11-25

### Fixed
- Improved permission error display in form modal
- Error message auto-hides when user edits fields

## [0.3.0] - 2025-11-25

### Added
- Granular authentication with prefix-based ACL
- Web UI users with username/password login (bcrypt)
- API tokens with bearer authentication
- Prefix-based permissions (`*`, `app/*`, exact match)
- Separate read/write/readwrite access levels
- Longest-match-first permission resolution
- Login rate limiting (5 concurrent attempts)
- HttpOnly/SameSite/Secure cookies

## [0.2.2] - 2025-11-24

### Fixed
- Git sync handles diverged remote histories gracefully
- Local commits preserved when pull/push fails
- Clear warning messages for manual conflict resolution

## [0.2.1] - 2025-11-24

### Added
- Dynamic modal sizing based on content
- Proper UTF-8 support for modal dimensions
- MkDocs documentation site

### Fixed
- Various mkdocs configuration issues

## [0.2.0] - 2025-11-24

### Added
- Git versioning for audit trail and point-in-time recovery
- `--git.enabled`, `--git.path`, `--git.remote`, `--git.push` flags
- `stash restore --rev=<commit>` command for database recovery
- Remote sync with auto-push to backup repository
- Debug logging for key operations

## [0.1.1] - 2025-11-24

### Added
- Responsive design for mobile and tablet devices
- Full-width card layout on mobile
- Full-screen modal on mobile devices

## [0.1.0] - 2025-11-24

Initial release.

### Added
- RESTful API for key-value operations (GET/PUT/DELETE)
- Web UI with HTMX for managing keys
- SQLite and PostgreSQL database support
- Token-based API authentication
- Session-based web authentication with prefix-based ACL
- Light/dark theme support
- Base URL support for subpath deployment
- Graceful shutdown and health checks
- Request throttling and size limits
