// Package store provides key-value storage implementations.
package store

import (
	"errors"
	"time"
)

// ErrNotFound is returned when a key is not found in the store.
var ErrNotFound = errors.New("key not found")

// ErrServiceNotFound is returned when a service instance is not found.
var ErrServiceNotFound = errors.New("service not found")

// KeyInfo holds metadata about a stored key.
type KeyInfo struct {
	Key       string    `db:"key"`
	Size      int       `db:"size"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// HealthCheckType defines how service health is verified.
type HealthCheckType string

// Health check type constants.
const (
	HealthCheckTTL  HealthCheckType = "ttl"  // service sends heartbeats
	HealthCheckHTTP HealthCheckType = "http" // stash polls HTTP endpoint
)

// ServiceInstance represents a registered service instance.
type ServiceInstance struct {
	ID            string          `json:"id" db:"id"`
	Name          string          `json:"name" db:"name"`
	Address       string          `json:"address" db:"address"`
	Port          int             `json:"port" db:"port"`
	Tags          []string        `json:"tags,omitempty" db:"-"`
	TagsJSON      string          `json:"-" db:"tags"` // for DB storage
	CheckType     HealthCheckType `json:"check_type" db:"check_type"`
	CheckURL      string          `json:"check_url,omitempty" db:"check_url"`
	CheckInterval int             `json:"check_interval" db:"check_interval"` // seconds, 0 = use global
	TTL           int             `json:"ttl" db:"ttl"`                       // seconds for TTL checks
	Healthy       bool            `json:"healthy" db:"healthy"`
	LastSeen      time.Time       `json:"last_seen" db:"last_seen"`
	RegisteredAt  time.Time       `json:"registered_at" db:"registered_at"`
}

// ServiceSummary provides aggregated info about a service.
type ServiceSummary struct {
	Name      string `json:"name" db:"name"`
	Instances int    `json:"instances" db:"instances"`
	Healthy   int    `json:"healthy" db:"healthy"`
}
