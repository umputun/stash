package stash

import (
	"errors"
	"fmt"
)

// sentinel errors for common API responses
var (
	ErrNotFound     = errors.New("key not found")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// ResponseError represents an HTTP error response from the server.
type ResponseError struct {
	StatusCode int
}

// Error implements the error interface.
func (e *ResponseError) Error() string {
	return fmt.Sprintf("stash: HTTP %d", e.StatusCode)
}
