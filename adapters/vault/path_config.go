/*
 * Q-TLS Configuration and Health Paths for HashiCorp Vault
 * Copyright 2025 QSIGN Project
 *
 * This file implements configuration, health check, and metrics endpoints.
 */

package qtls

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig returns the path for writing configuration
func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config$",

		Fields: map[string]*framework.FieldSchema{
			"pkcs11_library": {
				Type:        framework.TypeString,
				Description: "Path to PKCS#11 library for Luna HSM",
				Default:     "/usr/lib/libCryptoki2_64.so",
			},
			"token_label": {
				Type:        framework.TypeString,
				Description: "HSM token label",
				Default:     "vault",
			},
			"pin": {
				Type:        framework.TypeString,
				Description: "HSM token PIN",
			},
			"hybrid_mode": {
				Type:        framework.TypeBool,
				Description: "Enable hybrid cryptography mode",
				Default:     true,
			},
			"fips_mode": {
				Type:        framework.TypeBool,
				Description: "Enable FIPS 140-2 mode",
				Default:     true,
			},
			"qsign_root_ca": {
				Type:        framework.TypeString,
				Description: "Path to QSIGN root CA certificate",
			},
			"qsign_intermediate_ca": {
				Type:        framework.TypeString,
				Description: "Path to QSIGN intermediate CA certificate",
			},
			"max_sessions": {
				Type:        framework.TypeInt,
				Description: "Maximum HSM sessions",
				Default:     10,
			},
			"session_timeout": {
				Type:        framework.TypeInt,
				Description: "HSM session timeout in seconds",
				Default:     300,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWriteHandler,
				Summary:  "Configure the Q-TLS secrets engine",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWriteHandler,
				Summary:  "Configure the Q-TLS secrets engine",
			},
		},

		HelpSynopsis:    "Configure the Q-TLS secrets engine",
		HelpDescription: "Sets the configuration for Q-TLS operations including HSM connection parameters.",
	}
}

// pathConfigRead returns the path for reading configuration
func (b *backend) pathConfigRead() *framework.Path {
	return &framework.Path{
		Pattern: "config$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigReadHandler,
				Summary:  "Read Q-TLS configuration",
			},
		},

		HelpSynopsis:    "Read Q-TLS configuration",
		HelpDescription: "Returns the current configuration (sensitive values redacted).",
	}
}

// pathHealth returns the health check endpoint
func (b *backend) pathHealth() *framework.Path {
	return &framework.Path{
		Pattern: "health$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathHealthHandler,
				Summary:  "Check Q-TLS backend health",
			},
		},

		HelpSynopsis:    "Health check endpoint",
		HelpDescription: "Verifies HSM connectivity and backend status.",
	}
}

// pathMetrics returns the metrics endpoint
func (b *backend) pathMetrics() *framework.Path {
	return &framework.Path{
		Pattern: "metrics$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathMetricsHandler,
				Summary:  "Get backend metrics",
			},
		},

		HelpSynopsis:    "Backend metrics endpoint",
		HelpDescription: "Returns operational metrics for the Q-TLS backend.",
	}
}

// pathConfigWriteHandler handles configuration updates
func (b *backend) pathConfigWriteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	config := &BackendConfig{
		PKCS11Library:  data.Get("pkcs11_library").(string),
		TokenLabel:     data.Get("token_label").(string),
		PIN:            data.Get("pin").(string),
		HybridMode:     data.Get("hybrid_mode").(bool),
		FIPSMode:       data.Get("fips_mode").(bool),
		QSIGNRootCA:    data.Get("qsign_root_ca").(string),
		QSIGNIntermCA:  data.Get("qsign_intermediate_ca").(string),
		MaxSessions:    data.Get("max_sessions").(int),
		SessionTimeout: data.Get("session_timeout").(int),
	}

	// Validate configuration
	if config.PKCS11Library == "" {
		return errorResponse(fmt.Errorf("pkcs11_library is required"))
	}

	if config.TokenLabel == "" {
		return errorResponse(fmt.Errorf("token_label is required"))
	}

	if config.MaxSessions < 1 || config.MaxSessions > 100 {
		return errorResponse(fmt.Errorf("max_sessions must be between 1 and 100"))
	}

	// Store configuration
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Update in-memory config
	b.config = config

	// Reinitialize HSM pool if needed
	if b.hsmPool != nil {
		b.hsmPool.Close()
	}

	poolConfig := HSMPoolConfig{
		PKCS11Library:  config.PKCS11Library,
		TokenLabel:     config.TokenLabel,
		PIN:            config.PIN,
		MaxSessions:    config.MaxSessions,
		SessionTimeout: 300,
	}

	pool, err := NewHSMPool(poolConfig)
	if err != nil {
		return errorResponse(fmt.Errorf("failed to initialize HSM pool: %w", err))
	}

	b.hsmPool = pool
	b.Logger().Info("configuration updated and HSM pool reinitialized")

	return successResponse(map[string]interface{}{
		"message": "configuration updated successfully",
	})
}

// pathConfigReadHandler handles configuration reads
func (b *backend) pathConfigReadHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := b.getConfig()
	if config == nil {
		return nil, nil
	}

	// Return configuration with sensitive values redacted
	return successResponse(map[string]interface{}{
		"pkcs11_library":        config.PKCS11Library,
		"token_label":           config.TokenLabel,
		"pin":                   "<redacted>",
		"hybrid_mode":           config.HybridMode,
		"fips_mode":             config.FIPSMode,
		"qsign_root_ca":         config.QSIGNRootCA,
		"qsign_intermediate_ca": config.QSIGNIntermCA,
		"max_sessions":          config.MaxSessions,
		"session_timeout":       config.SessionTimeout,
	})
}

// pathHealthHandler handles health checks
func (b *backend) pathHealthHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	health := map[string]interface{}{
		"status": "healthy",
		"backend": "qtls",
	}

	// Check HSM connectivity
	if b.hsmPool != nil {
		if err := b.hsmPool.HealthCheck(); err != nil {
			health["status"] = "unhealthy"
			health["hsm_status"] = "disconnected"
			health["hsm_error"] = err.Error()
			return warningResponse("HSM health check failed", health)
		}

		hsmInfo, err := b.hsmPool.GetHSMInfo()
		if err == nil {
			health["hsm_status"] = "connected"
			health["hsm_info"] = hsmInfo
		}
	} else {
		health["hsm_status"] = "not configured"
	}

	// Add configuration status
	config := b.getConfig()
	if config != nil {
		health["hybrid_mode"] = config.HybridMode
		health["fips_mode"] = config.FIPSMode
	}

	return successResponse(health)
}

// pathMetricsHandler handles metrics requests
func (b *backend) pathMetricsHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	metrics := b.getMetrics()

	// Add HSM metrics if available
	if b.hsmPool != nil {
		hsmInfo, err := b.hsmPool.GetHSMInfo()
		if err == nil {
			metrics["hsm_sessions"] = hsmInfo
		}
	}

	return successResponse(metrics)
}

// Certificate management paths
func (b *backend) pathCertGenerate() *framework.Path {
	return &framework.Path{
		Pattern: "cert/generate",

		Fields: map[string]*framework.FieldSchema{
			"common_name": {
				Type:        framework.TypeString,
				Description: "Certificate common name",
				Required:    true,
			},
			"key_name": {
				Type:        framework.TypeString,
				Description: "Name of signing key to use",
				Required:    true,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Certificate TTL in seconds",
				Default:     31536000, // 1 year
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCertGenerateHandler,
				Summary:  "Generate a Q-TLS certificate",
			},
		},

		HelpSynopsis:    "Generate a quantum-resistant certificate",
		HelpDescription: "Generates a hybrid certificate with classical and PQC signatures.",
	}
}

func (b *backend) pathCertSign() *framework.Path {
	return &framework.Path{
		Pattern: "cert/sign",

		Fields: map[string]*framework.FieldSchema{
			"csr": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CSR",
				Required:    true,
			},
			"key_name": {
				Type:        framework.TypeString,
				Description: "Name of signing key",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCertSignHandler,
				Summary:  "Sign a certificate request",
			},
		},

		HelpSynopsis: "Sign a CSR with Q-TLS",
	}
}

func (b *backend) pathCertRevoke() *framework.Path {
	return &framework.Path{
		Pattern: "cert/revoke",

		Fields: map[string]*framework.FieldSchema{
			"serial_number": {
				Type:        framework.TypeString,
				Description: "Certificate serial number",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCertRevokeHandler,
				Summary:  "Revoke a certificate",
			},
		},

		HelpSynopsis: "Revoke a Q-TLS certificate",
	}
}

// Stub handlers for certificate operations
func (b *backend) pathCertGenerateHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return errorResponse(fmt.Errorf("certificate generation not yet implemented"))
}

func (b *backend) pathCertSignHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return errorResponse(fmt.Errorf("certificate signing not yet implemented"))
}

func (b *backend) pathCertRevokeHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return errorResponse(fmt.Errorf("certificate revocation not yet implemented"))
}
