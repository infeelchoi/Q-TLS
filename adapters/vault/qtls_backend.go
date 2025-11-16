/*
 * Q-TLS Secrets Engine Backend for HashiCorp Vault
 * Copyright 2025 QSIGN Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This backend provides quantum-resistant cryptographic operations for Vault,
 * integrating Q-TLS with Luna HSM for secure key management.
 */

package qtls

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// Backend configuration
	backendHelp = `
The Q-TLS secrets engine provides quantum-resistant cryptographic operations
using KYBER1024 for key encapsulation and DILITHIUM3 for digital signatures.

This backend integrates with Luna HSM via PKCS#11 for secure key storage and
supports the QSIGN PKI infrastructure for certificate management.

Features:
- KYBER1024 key generation and encapsulation
- DILITHIUM3 signature generation and verification
- Hybrid certificate management (classical + PQC)
- Luna HSM integration for FIPS 140-2 Level 3 compliance
- QSIGN PKI certificate issuance and validation
`

	// Key types
	KeyTypeKyber1024    = "kyber1024"
	KeyTypeDilithium3   = "dilithium3"
	KeyTypeHybrid       = "hybrid"

	// Operation types
	OpTypeEncapsulate   = "encapsulate"
	OpTypeDecapsulate   = "decapsulate"
	OpTypeSign          = "sign"
	OpTypeVerify        = "verify"
	OpTypeGenerate      = "generate"
)

// backend implements the Vault secrets engine interface
type backend struct {
	*framework.Backend

	// HSM connection pool
	hsmPool *HSMPool

	// Configuration
	config     *BackendConfig
	configLock sync.RWMutex

	// Metrics
	metrics *BackendMetrics
}

// BackendConfig stores the backend configuration
type BackendConfig struct {
	// HSM configuration
	PKCS11Library  string `json:"pkcs11_library"`
	TokenLabel     string `json:"token_label"`
	PIN            string `json:"pin"`

	// Q-TLS configuration
	HybridMode     bool   `json:"hybrid_mode"`
	FIPSMode       bool   `json:"fips_mode"`

	// QSIGN PKI configuration
	QSIGNRootCA    string `json:"qsign_root_ca"`
	QSIGNIntermCA  string `json:"qsign_intermediate_ca"`

	// Performance settings
	MaxSessions    int    `json:"max_sessions"`
	SessionTimeout int    `json:"session_timeout"`
}

// BackendMetrics tracks backend operations
type BackendMetrics struct {
	sync.RWMutex

	KeyGenerations    int64
	Encapsulations    int64
	Decapsulations    int64
	SignOperations    int64
	VerifyOperations  int64
	HSMOperations     int64
	Errors            int64

	LastOperation     time.Time
	LastError         time.Time
}

// Factory creates a new backend instance
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a new backend instance
func Backend() *backend {
	var b backend

	b.metrics = &BackendMetrics{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
				"keys/",
			},
		},

		Paths: []*framework.Path{
			// Configuration paths
			b.pathConfig(),
			b.pathConfigRead(),

			// Key management paths
			b.pathKeysList(),
			b.pathKeysWrite(),
			b.pathKeysRead(),
			b.pathKeysDelete(),

			// Cryptographic operation paths
			b.pathEncapsulate(),
			b.pathDecapsulate(),
			b.pathSign(),
			b.pathVerify(),

			// Certificate paths
			b.pathCertGenerate(),
			b.pathCertSign(),
			b.pathCertRevoke(),

			// Health and metrics paths
			b.pathHealth(),
			b.pathMetrics(),
		},

		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return &b
}

// Setup initializes the backend
func (b *backend) Setup(ctx context.Context, config *logical.BackendConfig) error {
	if err := b.Backend.Setup(ctx, config); err != nil {
		return err
	}

	// Load backend configuration
	if err := b.loadConfig(ctx, config.StorageView); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize HSM pool if configured
	if b.config != nil && b.config.PKCS11Library != "" {
		poolConfig := HSMPoolConfig{
			PKCS11Library:  b.config.PKCS11Library,
			TokenLabel:     b.config.TokenLabel,
			PIN:            b.config.PIN,
			MaxSessions:    b.config.MaxSessions,
			SessionTimeout: time.Duration(b.config.SessionTimeout) * time.Second,
		}

		pool, err := NewHSMPool(poolConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize HSM pool: %w", err)
		}

		b.hsmPool = pool
		b.Logger().Info("HSM pool initialized successfully",
			"library", b.config.PKCS11Library,
			"token", b.config.TokenLabel)
	}

	return nil
}

// loadConfig loads the backend configuration from storage
func (b *backend) loadConfig(ctx context.Context, storage logical.Storage) error {
	entry, err := storage.Get(ctx, "config")
	if err != nil {
		return err
	}

	if entry == nil {
		// No configuration stored, use defaults
		b.config = &BackendConfig{
			PKCS11Library:  "/usr/lib/libCryptoki2_64.so",
			TokenLabel:     "vault",
			HybridMode:     true,
			FIPSMode:       true,
			MaxSessions:    10,
			SessionTimeout: 300,
		}
		return nil
	}

	var config BackendConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return err
	}

	b.config = &config
	return nil
}

// invalidate is called when the backend is invalidated
func (b *backend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.configLock.Lock()
		defer b.configLock.Unlock()

		// Reload configuration
		if err := b.loadConfig(ctx, b.Backend.System().(*logical.InmemStorage)); err != nil {
			b.Logger().Error("failed to reload config", "error", err)
		}
	}
}

// Clean cleans up backend resources
func (b *backend) Clean(ctx context.Context) {
	if b.hsmPool != nil {
		b.hsmPool.Close()
	}
}

// getConfig safely returns the current configuration
func (b *backend) getConfig() *BackendConfig {
	b.configLock.RLock()
	defer b.configLock.RUnlock()
	return b.config
}

// updateMetrics updates operation metrics
func (b *backend) updateMetrics(opType string, success bool) {
	b.metrics.Lock()
	defer b.metrics.Unlock()

	b.metrics.LastOperation = time.Now()

	if !success {
		b.metrics.Errors++
		b.metrics.LastError = time.Now()
		return
	}

	switch opType {
	case OpTypeGenerate:
		b.metrics.KeyGenerations++
	case OpTypeEncapsulate:
		b.metrics.Encapsulations++
	case OpTypeDecapsulate:
		b.metrics.Decapsulations++
	case OpTypeSign:
		b.metrics.SignOperations++
	case OpTypeVerify:
		b.metrics.VerifyOperations++
	}
}

// getMetrics returns current metrics
func (b *backend) getMetrics() map[string]interface{} {
	b.metrics.RLock()
	defer b.metrics.RUnlock()

	return map[string]interface{}{
		"key_generations":    b.metrics.KeyGenerations,
		"encapsulations":     b.metrics.Encapsulations,
		"decapsulations":     b.metrics.Decapsulations,
		"sign_operations":    b.metrics.SignOperations,
		"verify_operations":  b.metrics.VerifyOperations,
		"hsm_operations":     b.metrics.HSMOperations,
		"errors":             b.metrics.Errors,
		"last_operation":     b.metrics.LastOperation.Unix(),
		"last_error":         b.metrics.LastError.Unix(),
	}
}

// KeyEntry represents a stored key
type KeyEntry struct {
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	PublicKey      []byte                 `json:"public_key"`
	HSMHandle      string                 `json:"hsm_handle,omitempty"`
	PrivateKey     []byte                 `json:"private_key,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`

	// For hybrid keys
	ClassicalPublicKey  []byte `json:"classical_public_key,omitempty"`
	ClassicalType       string `json:"classical_type,omitempty"`
}

// CertificateEntry represents a certificate
type CertificateEntry struct {
	SerialNumber   string    `json:"serial_number"`
	Certificate    []byte    `json:"certificate"`
	PrivateKeyName string    `json:"private_key_name"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked"`
	RevokedAt      time.Time `json:"revoked_at,omitempty"`
}

// Response helpers
func successResponse(data map[string]interface{}) (*logical.Response, error) {
	return &logical.Response{
		Data: data,
	}, nil
}

func errorResponse(err error) (*logical.Response, error) {
	return logical.ErrorResponse(err.Error()), nil
}

func warningResponse(warning string, data map[string]interface{}) (*logical.Response, error) {
	resp := &logical.Response{
		Data:     data,
		Warnings: []string{warning},
	}
	return resp, nil
}

// validateKeyType validates the key type
func validateKeyType(keyType string) error {
	switch keyType {
	case KeyTypeKyber1024, KeyTypeDilithium3, KeyTypeHybrid:
		return nil
	default:
		return fmt.Errorf("invalid key type: %s (must be kyber1024, dilithium3, or hybrid)", keyType)
	}
}

// Storage key helpers
func keysStorageKey(name string) string {
	return fmt.Sprintf("keys/%s", name)
}

func certsStorageKey(serial string) string {
	return fmt.Sprintf("certs/%s", serial)
}
