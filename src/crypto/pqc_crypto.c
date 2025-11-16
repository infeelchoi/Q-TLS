/*
 * Q-TLS: Quantum-Resistant Transport Security Layer
 * Post-Quantum Cryptography Implementation
 *
 * This module implements PQC operations using liboqs:
 * - KYBER1024 (ML-KEM-1024) for key encapsulation
 * - DILITHIUM3 (ML-DSA-65) for digital signatures
 * - Hybrid key derivation combining classical and PQC
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* Enable secure memory practices */
#ifdef FIPS_MODE
#include <openssl/fips.h>
#endif

/* Logging macros */
#ifdef ENABLE_LOGGING
#define LOG_INFO(fmt, ...) fprintf(stderr, "[QTLS-INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[QTLS-ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stderr, "[QTLS-DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)
#define LOG_ERROR(fmt, ...)
#define LOG_DEBUG(fmt, ...)
#endif

/*
 * Secure memory zeroing - constant time to prevent compiler optimization
 * Implements FIPS 140-2 requirement for secure key erasure
 */
void qtls_secure_zero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/*
 * Initialize OpenSSL and liboqs libraries
 * Must be called before any cryptographic operations
 */
static int qtls_crypto_init(void) {
    static int initialized = 0;

    if (initialized) {
        return QTLS_SUCCESS;
    }

#ifdef FIPS_MODE
    /* Enable FIPS mode if compiled with FIPS support */
    if (!FIPS_mode_set(1)) {
        LOG_ERROR("Failed to enable FIPS mode");
        return QTLS_ERROR_CRYPTO_INIT;
    }
    LOG_INFO("FIPS 140-2 mode enabled");
#endif

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();

    /* Verify liboqs is working */
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_1024)) {
        LOG_ERROR("KYBER1024 not available in liboqs");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        LOG_ERROR("DILITHIUM3 not available in liboqs");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    initialized = 1;
    LOG_INFO("Q-TLS crypto initialized (OpenSSL + liboqs)");
    return QTLS_SUCCESS;
}

/******************************************************************************
 * KYBER1024 (ML-KEM-1024) Implementation
 ******************************************************************************/

/*
 * Generate KYBER1024 keypair
 * Implements NIST FIPS 203 (ML-KEM)
 *
 * Security: NIST Level 5 (equivalent to AES-256)
 * Public key: 1568 bytes
 * Secret key: 3168 bytes
 */
int qtls_kyber_keygen(QTLS_KYBER_KEY *key) {
    OQS_KEM *kem = NULL;
    int ret = QTLS_ERROR_KEY_GENERATION;

    /* Validate input */
    if (key == NULL) {
        LOG_ERROR("qtls_kyber_keygen: NULL key pointer");
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Initialize crypto if needed */
    if (qtls_crypto_init() != QTLS_SUCCESS) {
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Clear key structure */
    qtls_secure_zero(key, sizeof(QTLS_KYBER_KEY));

    /* Initialize KYBER1024 */
    kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem == NULL) {
        LOG_ERROR("Failed to initialize KYBER1024");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Verify key sizes match our constants */
    if (kem->length_public_key != QTLS_KYBER1024_PUBLIC_KEY_BYTES ||
        kem->length_secret_key != QTLS_KYBER1024_SECRET_KEY_BYTES) {
        LOG_ERROR("KYBER1024 key size mismatch");
        OQS_KEM_free(kem);
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Generate keypair */
    LOG_DEBUG("Generating KYBER1024 keypair");
    if (OQS_KEM_keypair(kem, key->public_key, key->secret_key) != OQS_SUCCESS) {
        LOG_ERROR("KYBER1024 keypair generation failed");
        qtls_secure_zero(key, sizeof(QTLS_KYBER_KEY));
        OQS_KEM_free(kem);
        return QTLS_ERROR_KEY_GENERATION;
    }

    key->has_secret_key = 1;
    key->has_shared_secret = 0;
    ret = QTLS_SUCCESS;

    LOG_INFO("KYBER1024 keypair generated successfully");

    /* Cleanup */
    OQS_KEM_free(kem);
    return ret;
}

/*
 * KYBER1024 encapsulation (client side)
 * Encrypts a random shared secret to the server's public key
 *
 * Input: key->public_key (server's public key)
 * Output: key->ciphertext, key->shared_secret
 */
int qtls_kyber_encapsulate(QTLS_KYBER_KEY *key) {
    OQS_KEM *kem = NULL;
    int ret = QTLS_ERROR_ENCAPSULATION;

    /* Validate input */
    if (key == NULL) {
        LOG_ERROR("qtls_kyber_encapsulate: NULL key pointer");
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Initialize crypto if needed */
    if (qtls_crypto_init() != QTLS_SUCCESS) {
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Initialize KYBER1024 */
    kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem == NULL) {
        LOG_ERROR("Failed to initialize KYBER1024");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Verify ciphertext size */
    if (kem->length_ciphertext != QTLS_KYBER1024_CIPHERTEXT_BYTES ||
        kem->length_shared_secret != QTLS_KYBER1024_SHARED_SECRET_BYTES) {
        LOG_ERROR("KYBER1024 ciphertext/secret size mismatch");
        OQS_KEM_free(kem);
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Perform encapsulation */
    LOG_DEBUG("Performing KYBER1024 encapsulation");
    if (OQS_KEM_encaps(kem, key->ciphertext, key->shared_secret,
                       key->public_key) != OQS_SUCCESS) {
        LOG_ERROR("KYBER1024 encapsulation failed");
        qtls_secure_zero(key->shared_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
        OQS_KEM_free(kem);
        return QTLS_ERROR_ENCAPSULATION;
    }

    key->has_shared_secret = 1;
    ret = QTLS_SUCCESS;

    LOG_INFO("KYBER1024 encapsulation successful");

    /* Cleanup */
    OQS_KEM_free(kem);
    return ret;
}

/*
 * KYBER1024 decapsulation (server side)
 * Decrypts the shared secret using the server's secret key
 *
 * Input: key->secret_key, key->ciphertext
 * Output: key->shared_secret
 */
int qtls_kyber_decapsulate(QTLS_KYBER_KEY *key) {
    OQS_KEM *kem = NULL;
    int ret = QTLS_ERROR_DECAPSULATION;

    /* Validate input */
    if (key == NULL) {
        LOG_ERROR("qtls_kyber_decapsulate: NULL key pointer");
        return QTLS_ERROR_NULL_POINTER;
    }

    if (!key->has_secret_key) {
        LOG_ERROR("qtls_kyber_decapsulate: No secret key available");
        return QTLS_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize crypto if needed */
    if (qtls_crypto_init() != QTLS_SUCCESS) {
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Initialize KYBER1024 */
    kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem == NULL) {
        LOG_ERROR("Failed to initialize KYBER1024");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Perform decapsulation */
    LOG_DEBUG("Performing KYBER1024 decapsulation");
    if (OQS_KEM_decaps(kem, key->shared_secret, key->ciphertext,
                       key->secret_key) != OQS_SUCCESS) {
        LOG_ERROR("KYBER1024 decapsulation failed");
        qtls_secure_zero(key->shared_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
        OQS_KEM_free(kem);
        return QTLS_ERROR_DECAPSULATION;
    }

    key->has_shared_secret = 1;
    ret = QTLS_SUCCESS;

    LOG_INFO("KYBER1024 decapsulation successful");

    /* Cleanup */
    OQS_KEM_free(kem);
    return ret;
}

/******************************************************************************
 * DILITHIUM3 (ML-DSA-65) Implementation
 ******************************************************************************/

/*
 * Generate DILITHIUM3 keypair
 * Implements NIST FIPS 204 (ML-DSA)
 *
 * Security: NIST Level 3 (equivalent to AES-192)
 * Public key: 1952 bytes
 * Secret key: 4000 bytes
 * Signature: 3293 bytes
 */
int qtls_dilithium_keygen(QTLS_DILITHIUM_KEY *key) {
    OQS_SIG *sig = NULL;
    int ret = QTLS_ERROR_KEY_GENERATION;

    /* Validate input */
    if (key == NULL) {
        LOG_ERROR("qtls_dilithium_keygen: NULL key pointer");
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Initialize crypto if needed */
    if (qtls_crypto_init() != QTLS_SUCCESS) {
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Clear key structure */
    qtls_secure_zero(key, sizeof(QTLS_DILITHIUM_KEY));

    /* Initialize DILITHIUM3 */
    sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        LOG_ERROR("Failed to initialize DILITHIUM3");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Verify key sizes match our constants */
    if (sig->length_public_key != QTLS_DILITHIUM3_PUBLIC_KEY_BYTES ||
        sig->length_secret_key != QTLS_DILITHIUM3_SECRET_KEY_BYTES) {
        LOG_ERROR("DILITHIUM3 key size mismatch");
        OQS_SIG_free(sig);
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Generate keypair */
    LOG_DEBUG("Generating DILITHIUM3 keypair");
    if (OQS_SIG_keypair(sig, key->public_key, key->secret_key) != OQS_SUCCESS) {
        LOG_ERROR("DILITHIUM3 keypair generation failed");
        qtls_secure_zero(key, sizeof(QTLS_DILITHIUM_KEY));
        OQS_SIG_free(sig);
        return QTLS_ERROR_KEY_GENERATION;
    }

    key->has_secret_key = 1;
    ret = QTLS_SUCCESS;

    LOG_INFO("DILITHIUM3 keypair generated successfully");

    /* Cleanup */
    OQS_SIG_free(sig);
    return ret;
}

/*
 * DILITHIUM3 sign message
 * Creates a quantum-resistant digital signature
 *
 * Input: key->secret_key, msg, msg_len
 * Output: sig, sig_len
 */
int qtls_dilithium_sign(const QTLS_DILITHIUM_KEY *key,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t *sig, size_t *sig_len) {
    OQS_SIG *sig_ctx = NULL;
    int ret = QTLS_ERROR_SIGNATURE;

    /* Validate input */
    if (key == NULL || msg == NULL || sig == NULL || sig_len == NULL) {
        LOG_ERROR("qtls_dilithium_sign: NULL pointer argument");
        return QTLS_ERROR_NULL_POINTER;
    }

    if (!key->has_secret_key) {
        LOG_ERROR("qtls_dilithium_sign: No secret key available");
        return QTLS_ERROR_INVALID_ARGUMENT;
    }

    if (msg_len == 0) {
        LOG_ERROR("qtls_dilithium_sign: Empty message");
        return QTLS_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize crypto if needed */
    if (qtls_crypto_init() != QTLS_SUCCESS) {
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Initialize DILITHIUM3 */
    sig_ctx = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig_ctx == NULL) {
        LOG_ERROR("Failed to initialize DILITHIUM3");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Sign message */
    LOG_DEBUG("Signing message with DILITHIUM3 (msg_len=%zu)", msg_len);
    if (OQS_SIG_sign(sig_ctx, sig, sig_len, msg, msg_len,
                     key->secret_key) != OQS_SUCCESS) {
        LOG_ERROR("DILITHIUM3 signature generation failed");
        OQS_SIG_free(sig_ctx);
        return QTLS_ERROR_SIGNATURE;
    }

    /* Verify signature length */
    if (*sig_len > QTLS_DILITHIUM3_SIGNATURE_BYTES) {
        LOG_ERROR("DILITHIUM3 signature length exceeds maximum");
        OQS_SIG_free(sig_ctx);
        return QTLS_ERROR_SIGNATURE;
    }

    ret = QTLS_SUCCESS;
    LOG_INFO("DILITHIUM3 signature generated (sig_len=%zu)", *sig_len);

    /* Cleanup */
    OQS_SIG_free(sig_ctx);
    return ret;
}

/*
 * DILITHIUM3 verify signature
 * Verifies a quantum-resistant digital signature
 *
 * Input: key->public_key, msg, msg_len, sig, sig_len
 * Returns: 1 if valid, 0 if invalid, negative on error
 */
int qtls_dilithium_verify(const QTLS_DILITHIUM_KEY *key,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len) {
    OQS_SIG *sig_ctx = NULL;
    int ret = QTLS_ERROR_VERIFICATION;

    /* Validate input */
    if (key == NULL || msg == NULL || sig == NULL) {
        LOG_ERROR("qtls_dilithium_verify: NULL pointer argument");
        return QTLS_ERROR_NULL_POINTER;
    }

    if (msg_len == 0 || sig_len == 0) {
        LOG_ERROR("qtls_dilithium_verify: Empty message or signature");
        return QTLS_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize crypto if needed */
    if (qtls_crypto_init() != QTLS_SUCCESS) {
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Initialize DILITHIUM3 */
    sig_ctx = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig_ctx == NULL) {
        LOG_ERROR("Failed to initialize DILITHIUM3");
        return QTLS_ERROR_CRYPTO_INIT;
    }

    /* Verify signature */
    LOG_DEBUG("Verifying DILITHIUM3 signature (msg_len=%zu, sig_len=%zu)",
              msg_len, sig_len);
    if (OQS_SIG_verify(sig_ctx, msg, msg_len, sig, sig_len,
                       key->public_key) != OQS_SUCCESS) {
        LOG_ERROR("DILITHIUM3 signature verification failed");
        OQS_SIG_free(sig_ctx);
        return 0; /* Invalid signature */
    }

    ret = 1; /* Valid signature */
    LOG_INFO("DILITHIUM3 signature verified successfully");

    /* Cleanup */
    OQS_SIG_free(sig_ctx);
    return ret;
}

/******************************************************************************
 * Hybrid Key Derivation
 ******************************************************************************/

/*
 * Derive hybrid master secret
 * Combines ECDHE P-384 and KYBER1024 shared secrets using HKDF-SHA384
 *
 * Implements defense-in-depth: security holds if either classical
 * or PQC component remains secure.
 *
 * Input: secret->classical_secret, secret->pqc_secret,
 *        secret->client_random, secret->server_random
 * Output: secret->master_secret
 */
int qtls_derive_master_secret(QTLS_HYBRID_SECRET *secret) {
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t ikm[QTLS_ECDHE_P384_SHARED_SECRET_BYTES +
                QTLS_KYBER1024_SHARED_SECRET_BYTES];
    uint8_t salt[64]; /* client_random || server_random */
    size_t master_len = QTLS_MAX_MASTER_SECRET;
    int ret = QTLS_ERROR_KEY_DERIVATION;

    /* Validate input */
    if (secret == NULL) {
        LOG_ERROR("qtls_derive_master_secret: NULL secret pointer");
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Concatenate classical and PQC secrets as input keying material */
    memcpy(ikm, secret->classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memcpy(ikm + QTLS_ECDHE_P384_SHARED_SECRET_BYTES,
           secret->pqc_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);

    /* Concatenate randoms as salt */
    memcpy(salt, secret->client_random, QTLS_MAX_RANDOM_LEN);
    memcpy(salt + QTLS_MAX_RANDOM_LEN, secret->server_random, QTLS_MAX_RANDOM_LEN);

    /* Create HKDF context */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        LOG_ERROR("Failed to create HKDF context");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Initialize HKDF */
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        LOG_ERROR("HKDF initialization failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Set HKDF parameters: SHA-384 for higher security */
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384()) <= 0) {
        LOG_ERROR("HKDF set digest failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Set salt (client and server randoms) */
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt)) <= 0) {
        LOG_ERROR("HKDF set salt failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Set input keying material (concatenated secrets) */
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, sizeof(ikm)) <= 0) {
        LOG_ERROR("HKDF set key failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Set info string for domain separation */
    const uint8_t info[] = "Q-TLS hybrid master secret";
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info) - 1) <= 0) {
        LOG_ERROR("HKDF set info failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Derive master secret */
    LOG_DEBUG("Deriving hybrid master secret using HKDF-SHA384");
    if (EVP_PKEY_derive(pctx, secret->master_secret, &master_len) <= 0) {
        LOG_ERROR("HKDF derive failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    if (master_len != QTLS_MAX_MASTER_SECRET) {
        LOG_ERROR("HKDF produced unexpected master secret length: %zu", master_len);
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    ret = QTLS_SUCCESS;
    LOG_INFO("Hybrid master secret derived successfully (%zu bytes)", master_len);

cleanup:
    /* Secure cleanup */
    qtls_secure_zero(ikm, sizeof(ikm));
    qtls_secure_zero(salt, sizeof(salt));

    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return ret;
}

/*
 * Derive session keys from master secret
 * Derives AES-256 keys and IVs for both directions
 *
 * Input: secret->master_secret
 * Output: keys (client/server write keys and IVs)
 */
int qtls_derive_session_keys(const QTLS_HYBRID_SECRET *secret,
                              QTLS_SESSION_KEYS *keys) {
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t key_material[88]; /* 32+32+12+12 bytes */
    size_t key_material_len = sizeof(key_material);
    int ret = QTLS_ERROR_KEY_DERIVATION;

    /* Validate input */
    if (secret == NULL || keys == NULL) {
        LOG_ERROR("qtls_derive_session_keys: NULL pointer argument");
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Create HKDF context */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        LOG_ERROR("Failed to create HKDF context");
        return QTLS_ERROR_KEY_DERIVATION;
    }

    /* Initialize HKDF */
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        LOG_ERROR("HKDF initialization failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Set HKDF parameters */
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, secret->master_secret,
                                    QTLS_MAX_MASTER_SECRET) <= 0) {
        LOG_ERROR("HKDF parameter setup failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Set info for key expansion */
    const uint8_t info[] = "Q-TLS session keys";
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info) - 1) <= 0) {
        LOG_ERROR("HKDF set info failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Derive key material */
    LOG_DEBUG("Deriving session keys from master secret");
    if (EVP_PKEY_derive(pctx, key_material, &key_material_len) <= 0) {
        LOG_ERROR("Session key derivation failed");
        ret = QTLS_ERROR_KEY_DERIVATION;
        goto cleanup;
    }

    /* Split key material into individual keys and IVs */
    memcpy(keys->client_write_key, key_material, 32);
    memcpy(keys->server_write_key, key_material + 32, 32);
    memcpy(keys->client_write_iv, key_material + 64, 12);
    memcpy(keys->server_write_iv, key_material + 76, 12);

    ret = QTLS_SUCCESS;
    LOG_INFO("Session keys derived successfully");

cleanup:
    /* Secure cleanup */
    qtls_secure_zero(key_material, sizeof(key_material));

    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return ret;
}

/*
 * Get library version
 */
const char *qtls_version(void) {
    return QTLS_VERSION_STRING;
}

/*
 * Get error string for error code
 */
const char *qtls_get_error_string(int error) {
    switch (error) {
    case QTLS_SUCCESS:
        return "Success";
    case QTLS_ERROR_GENERIC:
        return "Generic error";
    case QTLS_ERROR_NULL_POINTER:
        return "NULL pointer argument";
    case QTLS_ERROR_INVALID_ARGUMENT:
        return "Invalid argument";
    case QTLS_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
    case QTLS_ERROR_CRYPTO_INIT:
        return "Cryptography initialization failed";
    case QTLS_ERROR_KEY_GENERATION:
        return "Key generation failed";
    case QTLS_ERROR_ENCAPSULATION:
        return "KEM encapsulation failed";
    case QTLS_ERROR_DECAPSULATION:
        return "KEM decapsulation failed";
    case QTLS_ERROR_SIGNATURE:
        return "Signature generation failed";
    case QTLS_ERROR_VERIFICATION:
        return "Signature verification failed";
    case QTLS_ERROR_KEY_DERIVATION:
        return "Key derivation failed";
    case QTLS_ERROR_HANDSHAKE_FAILED:
        return "TLS handshake failed";
    case QTLS_ERROR_HSM_NOT_AVAILABLE:
        return "HSM not available";
    default:
        return "Unknown error";
    }
}
