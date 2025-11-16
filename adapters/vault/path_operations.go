/*
 * Q-TLS Cryptographic Operations Paths for HashiCorp Vault
 * Copyright 2025 QSIGN Project
 *
 * This file implements cryptographic operation endpoints for encapsulation,
 * decapsulation, signing, and verification.
 */

package qtls

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathEncapsulate returns the path for KYBER encapsulation
func (b *backend) pathEncapsulate() *framework.Path {
	return &framework.Path{
		Pattern: "encapsulate/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the KYBER1024 key",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncapsulateHandler,
				Summary:  "Encapsulate using KYBER1024 public key",
			},
		},

		HelpSynopsis:    "Encapsulate a shared secret using KYBER1024",
		HelpDescription: "Generates a ciphertext and shared secret using the specified KYBER1024 public key.",
	}
}

// pathDecapsulate returns the path for KYBER decapsulation
func (b *backend) pathDecapsulate() *framework.Path {
	return &framework.Path{
		Pattern: "decapsulate/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the KYBER1024 key",
				Required:    true,
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "Base64-encoded ciphertext to decapsulate",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecapsulateHandler,
				Summary:  "Decapsulate using KYBER1024 private key",
			},
		},

		HelpSynopsis:    "Decapsulate a ciphertext using KYBER1024",
		HelpDescription: "Decapsulates the ciphertext to recover the shared secret using the private key.",
	}
}

// pathSign returns the path for DILITHIUM signing
func (b *backend) pathSign() *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the DILITHIUM3 key",
				Required:    true,
			},
			"message": {
				Type:        framework.TypeString,
				Description: "Base64-encoded message to sign",
				Required:    true,
			},
			"prehashed": {
				Type:        framework.TypeBool,
				Description: "Whether the message is already hashed",
				Default:     false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignHandler,
				Summary:  "Sign a message using DILITHIUM3",
			},
		},

		HelpSynopsis:    "Sign a message using DILITHIUM3",
		HelpDescription: "Generates a quantum-resistant signature for the specified message.",
	}
}

// pathVerify returns the path for DILITHIUM verification
func (b *backend) pathVerify() *framework.Path {
	return &framework.Path{
		Pattern: "verify/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the DILITHIUM3 key",
				Required:    true,
			},
			"message": {
				Type:        framework.TypeString,
				Description: "Base64-encoded message that was signed",
				Required:    true,
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "Base64-encoded signature to verify",
				Required:    true,
			},
			"prehashed": {
				Type:        framework.TypeBool,
				Description: "Whether the message is already hashed",
				Default:     false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVerifyHandler,
				Summary:  "Verify a DILITHIUM3 signature",
			},
		},

		HelpSynopsis:    "Verify a DILITHIUM3 signature",
		HelpDescription: "Verifies a quantum-resistant signature against the message and public key.",
	}
}

// pathEncapsulateHandler handles KYBER encapsulation
func (b *backend) pathEncapsulateHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	// Get the key
	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		b.updateMetrics(OpTypeEncapsulate, false)
		return nil, err
	}

	if key == nil {
		b.updateMetrics(OpTypeEncapsulate, false)
		return errorResponse(fmt.Errorf("key %s not found", name))
	}

	// Validate key type
	if key.Type != KeyTypeKyber1024 && key.Type != KeyTypeHybrid {
		b.updateMetrics(OpTypeEncapsulate, false)
		return errorResponse(fmt.Errorf("key %s is not a KYBER1024 key", name))
	}

	// Perform encapsulation
	var ciphertext, sharedSecret []byte

	if b.hsmPool != nil {
		// Use HSM
		ciphertext, sharedSecret, err = b.hsmPool.HSMEncapsulate(key.PublicKey)
		if err != nil {
			b.updateMetrics(OpTypeEncapsulate, false)
			return errorResponse(fmt.Errorf("HSM encapsulation failed: %w", err))
		}
	} else {
		// Software implementation (for demonstration)
		// In production, use liboqs
		b.updateMetrics(OpTypeEncapsulate, false)
		return errorResponse(fmt.Errorf("software encapsulation not implemented"))
	}

	b.updateMetrics(OpTypeEncapsulate, true)
	b.Logger().Info("encapsulation successful", "key", name)

	return successResponse(map[string]interface{}{
		"ciphertext":    base64.StdEncoding.EncodeToString(ciphertext),
		"shared_secret": base64.StdEncoding.EncodeToString(sharedSecret),
		"algorithm":     "KYBER1024",
	})
}

// pathDecapsulateHandler handles KYBER decapsulation
func (b *backend) pathDecapsulateHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	ciphertextB64 := data.Get("ciphertext").(string)

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		b.updateMetrics(OpTypeDecapsulate, false)
		return errorResponse(fmt.Errorf("invalid ciphertext encoding: %w", err))
	}

	// Get the key
	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		b.updateMetrics(OpTypeDecapsulate, false)
		return nil, err
	}

	if key == nil {
		b.updateMetrics(OpTypeDecapsulate, false)
		return errorResponse(fmt.Errorf("key %s not found", name))
	}

	// Validate key type
	if key.Type != KeyTypeKyber1024 && key.Type != KeyTypeHybrid {
		b.updateMetrics(OpTypeDecapsulate, false)
		return errorResponse(fmt.Errorf("key %s is not a KYBER1024 key", name))
	}

	// Validate key has private key access
	if key.HSMHandle == "" && len(key.PrivateKey) == 0 {
		b.updateMetrics(OpTypeDecapsulate, false)
		return errorResponse(fmt.Errorf("key %s has no private key", name))
	}

	// Perform decapsulation
	var sharedSecret []byte

	if key.HSMHandle != "" && b.hsmPool != nil {
		// Use HSM
		sharedSecret, err = b.hsmPool.HSMDecapsulate(key.HSMHandle, ciphertext)
		if err != nil {
			b.updateMetrics(OpTypeDecapsulate, false)
			return errorResponse(fmt.Errorf("HSM decapsulation failed: %w", err))
		}
	} else {
		// Software implementation
		b.updateMetrics(OpTypeDecapsulate, false)
		return errorResponse(fmt.Errorf("software decapsulation not implemented"))
	}

	b.updateMetrics(OpTypeDecapsulate, true)
	b.Logger().Info("decapsulation successful", "key", name)

	return successResponse(map[string]interface{}{
		"shared_secret": base64.StdEncoding.EncodeToString(sharedSecret),
		"algorithm":     "KYBER1024",
	})
}

// pathSignHandler handles DILITHIUM signing
func (b *backend) pathSignHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	messageB64 := data.Get("message").(string)
	prehashed := data.Get("prehashed").(bool)

	// Decode message
	message, err := base64.StdEncoding.DecodeString(messageB64)
	if err != nil {
		b.updateMetrics(OpTypeSign, false)
		return errorResponse(fmt.Errorf("invalid message encoding: %w", err))
	}

	// Get the key
	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		b.updateMetrics(OpTypeSign, false)
		return nil, err
	}

	if key == nil {
		b.updateMetrics(OpTypeSign, false)
		return errorResponse(fmt.Errorf("key %s not found", name))
	}

	// Validate key type
	if key.Type != KeyTypeDilithium3 && key.Type != KeyTypeHybrid {
		b.updateMetrics(OpTypeSign, false)
		return errorResponse(fmt.Errorf("key %s is not a DILITHIUM3 key", name))
	}

	// Validate key has private key access
	if key.HSMHandle == "" && len(key.PrivateKey) == 0 {
		b.updateMetrics(OpTypeSign, false)
		return errorResponse(fmt.Errorf("key %s has no private key", name))
	}

	// Perform signing
	var signature []byte

	if key.HSMHandle != "" && b.hsmPool != nil {
		// Use HSM
		signature, err = b.hsmPool.HSMSign(key.HSMHandle, message)
		if err != nil {
			b.updateMetrics(OpTypeSign, false)
			return errorResponse(fmt.Errorf("HSM signing failed: %w", err))
		}
	} else {
		// Software implementation
		b.updateMetrics(OpTypeSign, false)
		return errorResponse(fmt.Errorf("software signing not implemented"))
	}

	b.updateMetrics(OpTypeSign, true)
	b.Logger().Info("signing successful", "key", name, "message_size", len(message))

	return successResponse(map[string]interface{}{
		"signature":  base64.StdEncoding.EncodeToString(signature),
		"algorithm":  "DILITHIUM3",
		"prehashed":  prehashed,
	})
}

// pathVerifyHandler handles DILITHIUM verification
func (b *backend) pathVerifyHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	messageB64 := data.Get("message").(string)
	signatureB64 := data.Get("signature").(string)
	prehashed := data.Get("prehashed").(bool)

	// Decode message and signature
	message, err := base64.StdEncoding.DecodeString(messageB64)
	if err != nil {
		b.updateMetrics(OpTypeVerify, false)
		return errorResponse(fmt.Errorf("invalid message encoding: %w", err))
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		b.updateMetrics(OpTypeVerify, false)
		return errorResponse(fmt.Errorf("invalid signature encoding: %w", err))
	}

	// Get the key
	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		b.updateMetrics(OpTypeVerify, false)
		return nil, err
	}

	if key == nil {
		b.updateMetrics(OpTypeVerify, false)
		return errorResponse(fmt.Errorf("key %s not found", name))
	}

	// Validate key type
	if key.Type != KeyTypeDilithium3 && key.Type != KeyTypeHybrid {
		b.updateMetrics(OpTypeVerify, false)
		return errorResponse(fmt.Errorf("key %s is not a DILITHIUM3 key", name))
	}

	// Perform verification
	var valid bool

	if b.hsmPool != nil {
		// Use HSM
		valid, err = b.hsmPool.HSMVerify(key.PublicKey, message, signature)
		if err != nil {
			b.updateMetrics(OpTypeVerify, false)
			return errorResponse(fmt.Errorf("HSM verification failed: %w", err))
		}
	} else {
		// Software implementation
		b.updateMetrics(OpTypeVerify, false)
		return errorResponse(fmt.Errorf("software verification not implemented"))
	}

	b.updateMetrics(OpTypeVerify, true)
	b.Logger().Info("verification completed", "key", name, "valid", valid)

	return successResponse(map[string]interface{}{
		"valid":      valid,
		"algorithm":  "DILITHIUM3",
		"prehashed":  prehashed,
	})
}
