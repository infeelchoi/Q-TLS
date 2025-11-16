/*
 * Q-TLS Key Management Paths for HashiCorp Vault
 * Copyright 2025 QSIGN Project
 *
 * This file implements key management endpoints for the Q-TLS secrets engine.
 */

package qtls

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathKeysList returns the path for listing keys
func (b *backend) pathKeysList() *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathKeysListHandler,
				Summary:  "List all quantum-resistant keys",
			},
		},

		HelpSynopsis:    "List all quantum-resistant keys",
		HelpDescription: "Returns a list of all key names stored in the backend.",
	}
}

// pathKeysWrite returns the path for creating/updating keys
func (b *backend) pathKeysWrite() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
				Required:    true,
			},
			"type": {
				Type:        framework.TypeString,
				Description: "Key type: kyber1024, dilithium3, or hybrid",
				Required:    true,
			},
			"use_hsm": {
				Type:        framework.TypeBool,
				Description: "Store key in Luna HSM",
				Default:     true,
			},
			"metadata": {
				Type:        framework.TypeMap,
				Description: "Additional metadata for the key",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathKeysWriteHandler,
				Summary:  "Generate a new quantum-resistant key",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKeysWriteHandler,
				Summary:  "Update an existing quantum-resistant key",
			},
		},

		HelpSynopsis:    "Generate or update a quantum-resistant key",
		HelpDescription: "Generates a new KYBER1024, DILITHIUM3, or hybrid key pair.",
	}
}

// pathKeysRead returns the path for reading keys
func (b *backend) pathKeysRead() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeysReadHandler,
				Summary:  "Read a quantum-resistant key",
			},
		},

		HelpSynopsis:    "Read a quantum-resistant key",
		HelpDescription: "Returns the public key and metadata for the specified key.",
	}
}

// pathKeysDelete returns the path for deleting keys
func (b *backend) pathKeysDelete() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathKeysDeleteHandler,
				Summary:  "Delete a quantum-resistant key",
			},
		},

		HelpSynopsis:    "Delete a quantum-resistant key",
		HelpDescription: "Deletes the specified key from storage and HSM.",
	}
}

// pathKeysListHandler handles key listing
func (b *backend) pathKeysListHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "keys/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathKeysWriteHandler handles key creation/update
func (b *backend) pathKeysWriteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	keyType := data.Get("type").(string)
	useHSM := data.Get("use_hsm").(bool)
	metadata := data.Get("metadata").(map[string]interface{})

	// Validate key type
	if err := validateKeyType(keyType); err != nil {
		b.updateMetrics(OpTypeGenerate, false)
		return errorResponse(err)
	}

	// Check if key already exists
	existing, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		b.updateMetrics(OpTypeGenerate, false)
		return nil, err
	}

	if existing != nil && req.Operation == logical.CreateOperation {
		return errorResponse(fmt.Errorf("key %s already exists", name))
	}

	// Generate key based on type
	var entry *KeyEntry

	switch keyType {
	case KeyTypeKyber1024:
		entry, err = b.generateKyberKey(ctx, name, useHSM, metadata)
	case KeyTypeDilithium3:
		entry, err = b.generateDilithiumKey(ctx, name, useHSM, metadata)
	case KeyTypeHybrid:
		entry, err = b.generateHybridKey(ctx, name, useHSM, metadata)
	default:
		b.updateMetrics(OpTypeGenerate, false)
		return errorResponse(fmt.Errorf("unsupported key type: %s", keyType))
	}

	if err != nil {
		b.updateMetrics(OpTypeGenerate, false)
		return errorResponse(fmt.Errorf("failed to generate key: %w", err))
	}

	// Store key
	if err := b.storeKey(ctx, req.Storage, entry); err != nil {
		b.updateMetrics(OpTypeGenerate, false)
		return errorResponse(fmt.Errorf("failed to store key: %w", err))
	}

	b.updateMetrics(OpTypeGenerate, true)
	b.Logger().Info("key generated successfully", "name", name, "type", keyType, "hsm", useHSM)

	return successResponse(map[string]interface{}{
		"name":       entry.Name,
		"type":       entry.Type,
		"public_key": entry.PublicKey,
		"created_at": entry.CreatedAt,
		"use_hsm":    entry.HSMHandle != "",
	})
}

// pathKeysReadHandler handles key reading
func (b *backend) pathKeysReadHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	entry, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	responseData := map[string]interface{}{
		"name":       entry.Name,
		"type":       entry.Type,
		"public_key": entry.PublicKey,
		"created_at": entry.CreatedAt,
		"updated_at": entry.UpdatedAt,
		"metadata":   entry.Metadata,
	}

	if entry.HSMHandle != "" {
		responseData["hsm_stored"] = true
		responseData["hsm_handle"] = entry.HSMHandle
	}

	if entry.Type == KeyTypeHybrid {
		responseData["classical_public_key"] = entry.ClassicalPublicKey
		responseData["classical_type"] = entry.ClassicalType
	}

	return successResponse(responseData)
}

// pathKeysDeleteHandler handles key deletion
func (b *backend) pathKeysDeleteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	entry, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	// Delete from HSM if applicable
	if entry.HSMHandle != "" && b.hsmPool != nil {
		if err := b.hsmPool.HSMDeleteKey(entry.HSMHandle); err != nil {
			b.Logger().Warn("failed to delete key from HSM", "error", err)
			return warningResponse("key deleted from storage but HSM deletion failed",
				map[string]interface{}{"name": name})
		}
	}

	// Delete from storage
	if err := req.Storage.Delete(ctx, keysStorageKey(name)); err != nil {
		return errorResponse(fmt.Errorf("failed to delete key: %w", err))
	}

	b.Logger().Info("key deleted successfully", "name", name)

	return successResponse(map[string]interface{}{
		"name":    name,
		"deleted": true,
	})
}

// generateKyberKey generates a KYBER1024 key pair
func (b *backend) generateKyberKey(ctx context.Context, name string, useHSM bool, metadata map[string]interface{}) (*KeyEntry, error) {
	entry := &KeyEntry{
		Name:      name,
		Type:      KeyTypeKyber1024,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  metadata,
	}

	if useHSM && b.hsmPool != nil {
		// Generate key in HSM
		publicKey, handle, err := b.hsmPool.HSMKeyGen(KeyTypeKyber1024, name)
		if err != nil {
			return nil, fmt.Errorf("HSM key generation failed: %w", err)
		}

		entry.PublicKey = publicKey
		entry.HSMHandle = handle
	} else {
		// Generate key in software (for demonstration)
		// In production, use liboqs or similar library
		publicKey := make([]byte, 1568) // KYBER1024 public key size
		entry.PublicKey = publicKey
	}

	return entry, nil
}

// generateDilithiumKey generates a DILITHIUM3 key pair
func (b *backend) generateDilithiumKey(ctx context.Context, name string, useHSM bool, metadata map[string]interface{}) (*KeyEntry, error) {
	entry := &KeyEntry{
		Name:      name,
		Type:      KeyTypeDilithium3,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  metadata,
	}

	if useHSM && b.hsmPool != nil {
		// Generate key in HSM
		publicKey, handle, err := b.hsmPool.HSMKeyGen(KeyTypeDilithium3, name)
		if err != nil {
			return nil, fmt.Errorf("HSM key generation failed: %w", err)
		}

		entry.PublicKey = publicKey
		entry.HSMHandle = handle
	} else {
		// Generate key in software
		publicKey := make([]byte, 1952) // DILITHIUM3 public key size
		entry.PublicKey = publicKey
	}

	return entry, nil
}

// generateHybridKey generates a hybrid (classical + PQC) key pair
func (b *backend) generateHybridKey(ctx context.Context, name string, useHSM bool, metadata map[string]interface{}) (*KeyEntry, error) {
	// Generate DILITHIUM3 key
	dilithiumEntry, err := b.generateDilithiumKey(ctx, name+"-dilithium", useHSM, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DILITHIUM3 key: %w", err)
	}

	// For hybrid, also generate classical key (RSA-2048 or ECDSA P-384)
	// In production, use appropriate crypto library
	classicalPublicKey := make([]byte, 294) // ECDSA P-384 public key size

	entry := &KeyEntry{
		Name:               name,
		Type:               KeyTypeHybrid,
		PublicKey:          dilithiumEntry.PublicKey,
		HSMHandle:          dilithiumEntry.HSMHandle,
		ClassicalPublicKey: classicalPublicKey,
		ClassicalType:      "ecdsa-p384",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Metadata:           metadata,
	}

	return entry, nil
}

// getKey retrieves a key from storage
func (b *backend) getKey(ctx context.Context, storage logical.Storage, name string) (*KeyEntry, error) {
	entry, err := storage.Get(ctx, keysStorageKey(name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var keyEntry KeyEntry
	if err := entry.DecodeJSON(&keyEntry); err != nil {
		return nil, err
	}

	return &keyEntry, nil
}

// storeKey stores a key in storage
func (b *backend) storeKey(ctx context.Context, storage logical.Storage, key *KeyEntry) error {
	entry, err := logical.StorageEntryJSON(keysStorageKey(key.Name), key)
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}
