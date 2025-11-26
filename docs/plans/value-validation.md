# Value Validation for Known Formats

## Overview
Add server-side validation for known data formats (json, yaml, xml, toml, ini) when creating or editing keys via web UI. If validation fails, show error with option to "submit anyway" - allowing users to either fix the issue or bypass validation.

## Context
- files involved: `app/server/web.go` (handlers), `app/server/templates/partials/form.html` (UI)
- new package: `app/validator/` for validation logic
- formats to validate: json, yaml, xml, toml, ini (text and shell skip validation)
- flow: htmx form submit → server validates → returns form with error OR saves value

## Iterative Development Approach
- complete each step fully before moving to the next
- make small, focused changes
- **CRITICAL: every iteration must end with adding/updating tests**
- **CRITICAL: all tests must pass before starting next iteration**
- run tests after each change
- maintain backward compatibility

## Progress Tracking
- mark completed items with `[x]`
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix

## Implementation Steps

### Iteration 1: Create Validator Package ✅
- [x] create `app/validator/validator.go` with `Validate(format string, value []byte) error`
- [x] implement json validation using `encoding/json`
- [x] implement yaml validation using `gopkg.in/yaml.v3`
- [x] implement xml validation using `encoding/xml`
- [x] implement toml validation using `github.com/BurntSushi/toml`
- [x] implement ini validation using `gopkg.in/ini.v1`
- [x] **create `app/validator/validator_test.go` with tests:**
  - [x] test valid json passes
  - [x] test invalid json returns error
  - [x] test valid yaml passes
  - [x] test invalid yaml returns error
  - [x] test valid xml passes
  - [x] test invalid xml returns error
  - [x] test valid toml passes
  - [x] test invalid toml returns error
  - [x] test valid ini passes
  - [x] test invalid ini returns error
  - [x] test "text" format skips validation
  - [x] test "shell" format skips validation
  - [x] test unknown format skips validation
- [x] **run `go test ./app/validator/...` - 100% coverage, all tests pass**

### Iteration 2: Integrate Validation in Handlers ✅
- [x] modify `handleKeyCreate` in `web.go` to call `validator.Validate()` before storing
- [x] modify `handleKeyUpdate` in `web.go` to call `validator.Validate()` before storing
- [x] add `force` form field support to bypass validation
- [x] return form with error message when validation fails (using existing error pattern)
- [x] **add tests in `web_test.go`:**
  - [x] test create with valid json succeeds
  - [x] test create with invalid json returns form with error
  - [x] test create with invalid json + force=true succeeds
  - [x] test update with valid yaml succeeds
  - [x] test update with invalid yaml returns form with error
  - [x] test update with invalid yaml + force=true succeeds
  - [x] test text format bypasses validation
- [x] **run `go test ./...` - all tests pass**

### Iteration 3: Update Form Template ✅
- [x] modify `form.html` to show "submit anyway" button when `.Error` is set
- [x] style "submit anyway" button appropriately (uses btn-danger for warning)
- [x] ensure form resubmission with `force=true` works correctly
- [x] **manual testing of UI flow:**
  - [x] create key with invalid json → see error → click "submit anyway" → key created
  - [x] edit key with valid json → saves without warning
- [x] **run `go test ./...` - all tests pass**

### Iteration 4: Documentation & Cleanup ✅
- [x] dependencies added to go.mod (gopkg.in/yaml.v3, github.com/BurntSushi/toml, gopkg.in/ini.v1)
- [x] code cleanup and formatting - all clean
- [x] linter passes - 0 issues
- [x] **all tests pass with good coverage:**
  - validator: 100%
  - server: 86.8%
  - store: 86.7%

## Technical Details

### Validator API
```go
package validator

// Validate checks if value is valid for the given format.
// Returns nil for text, shell, or unknown formats (no validation).
// Returns descriptive error for invalid json, yaml, xml, toml, ini.
func Validate(format string, value []byte) error
```

### Dependencies to Add
```
gopkg.in/yaml.v3
github.com/BurntSushi/toml
gopkg.in/ini.v1
```

### Form Flow
1. user submits form via htmx
2. handler parses form, calls `validator.Validate(format, value)`
3. if error AND `force != "true"`: return form template with error, show "submit anyway"
4. if no error OR `force == "true"`: proceed with store.Set()

### Error Display
- reuse existing `.Error` field in templateData
- error message from validator shown in form
- two buttons when error: "Save" (resubmit without force) and "Submit Anyway" (with force=true)
