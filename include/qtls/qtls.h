/*
 * Q-TLS: 양자 내성 전송 보안 계층
 * Copyright 2025 QSIGN Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * 하이브리드 암호화(고전 + PQC)를 사용하여 양자 내성
 * TLS 구현을 제공하는 Q-TLS 라이브러리의 메인 API 헤더입니다.
 */

#ifndef QTLS_H
#define QTLS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version information */
#define QTLS_VERSION_MAJOR 1
#define QTLS_VERSION_MINOR 0
#define QTLS_VERSION_PATCH 0
#define QTLS_VERSION_STRING "1.0.0"

/* Operating modes */
#define QTLS_CLIENT_MODE 0
#define QTLS_SERVER_MODE 1

/* Protocol versions */
#define QTLS_VERSION_1_3 0x0304

/* Algorithm identifiers */
/* Post-Quantum KEMs (NIST standardized) */
#define QTLS_KEM_KYBER512     0x0001
#define QTLS_KEM_KYBER768     0x0002
#define QTLS_KEM_KYBER1024    0x0003  /* Default - highest security */

/* Post-Quantum Signatures (NIST standardized) */
#define QTLS_SIG_DILITHIUM2   0x0101
#define QTLS_SIG_DILITHIUM3   0x0102  /* Default - highest security */
#define QTLS_SIG_DILITHIUM5   0x0103

/* Classical KEMs */
#define QTLS_KEM_ECDHE_P256   0x0201
#define QTLS_KEM_ECDHE_P384   0x0202  /* Default for hybrid */
#define QTLS_KEM_ECDHE_P521   0x0203

/* Classical Signatures */
#define QTLS_SIG_RSA_2048     0x0301
#define QTLS_SIG_RSA_4096     0x0302
#define QTLS_SIG_ECDSA_P256   0x0303
#define QTLS_SIG_ECDSA_P384   0x0304

/* Symmetric ciphers */
#define QTLS_CIPHER_AES_128_GCM      0x0401
#define QTLS_CIPHER_AES_256_GCM      0x0402  /* Default */
#define QTLS_CIPHER_CHACHA20_POLY1305 0x0403

/* Context options */
#define QTLS_OP_NO_SSLv2              0x00000001
#define QTLS_OP_NO_SSLv3              0x00000002
#define QTLS_OP_NO_TLSv1              0x00000004
#define QTLS_OP_NO_TLSv1_1            0x00000008
#define QTLS_OP_NO_TLSv1_2            0x00000010
#define QTLS_OP_HYBRID_MODE           0x00000100  /* Enable PQC hybrid */
#define QTLS_OP_PQC_ONLY              0x00000200  /* PQC only (experimental) */
#define QTLS_OP_CLASSICAL_ONLY        0x00000400  /* Classical only */

/* Verification modes */
#define QTLS_VERIFY_NONE               0x00
#define QTLS_VERIFY_PEER               0x01
#define QTLS_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define QTLS_VERIFY_CLIENT_ONCE        0x04

/* File types */
#define QTLS_FILETYPE_PEM     1
#define QTLS_FILETYPE_ASN1    2

/* Error codes */
#define QTLS_SUCCESS                    0
#define QTLS_ERROR_NONE                 0
#define QTLS_ERROR_GENERIC             -1
#define QTLS_ERROR_NULL_POINTER        -2
#define QTLS_ERROR_INVALID_ARGUMENT    -3
#define QTLS_ERROR_OUT_OF_MEMORY       -4
#define QTLS_ERROR_SYSCALL             -5
#define QTLS_ERROR_WANT_READ           -6
#define QTLS_ERROR_WANT_WRITE          -7
#define QTLS_ERROR_ZERO_RETURN         -8

/* Crypto errors */
#define QTLS_ERROR_CRYPTO_INIT         -100
#define QTLS_ERROR_KEY_GENERATION      -101
#define QTLS_ERROR_ENCAPSULATION       -102
#define QTLS_ERROR_DECAPSULATION       -103
#define QTLS_ERROR_SIGNATURE           -104
#define QTLS_ERROR_VERIFICATION        -105
#define QTLS_ERROR_KEY_DERIVATION      -106
#define QTLS_ERROR_ENCRYPTION          -107
#define QTLS_ERROR_DECRYPTION          -108

/* Protocol errors */
#define QTLS_ERROR_HANDSHAKE_FAILED    -200
#define QTLS_ERROR_PROTOCOL_VERSION    -201
#define QTLS_ERROR_CERT_VERIFY_FAILED  -202
#define QTLS_ERROR_PEER_CLOSED         -203
#define QTLS_ERROR_INVALID_MESSAGE     -204
#define QTLS_ERROR_UNSUPPORTED_ALGO    -205

/* HSM errors */
#define QTLS_ERROR_HSM_NOT_AVAILABLE   -300
#define QTLS_ERROR_HSM_INIT_FAILED     -301
#define QTLS_ERROR_HSM_LOGIN_FAILED    -302
#define QTLS_ERROR_HSM_KEY_NOT_FOUND   -303
#define QTLS_ERROR_HSM_OPERATION_FAILED -304

/* Maximum sizes */
#define QTLS_MAX_CERT_CHAIN_LEN   10
#define QTLS_MAX_SESSION_ID_LEN   32
#define QTLS_MAX_RANDOM_LEN       32
#define QTLS_MAX_MASTER_SECRET    48

/* KYBER1024 constants (ML-KEM-1024) */
#define QTLS_KYBER1024_PUBLIC_KEY_BYTES   1568
#define QTLS_KYBER1024_SECRET_KEY_BYTES   3168
#define QTLS_KYBER1024_CIPHERTEXT_BYTES   1568
#define QTLS_KYBER1024_SHARED_SECRET_BYTES 32

/* DILITHIUM3 constants (ML-DSA-65) */
#define QTLS_DILITHIUM3_PUBLIC_KEY_BYTES  1952
#define QTLS_DILITHIUM3_SECRET_KEY_BYTES  4000
#define QTLS_DILITHIUM3_SIGNATURE_BYTES   3293

/* ECDHE P-384 constants */
#define QTLS_ECDHE_P384_PUBLIC_KEY_BYTES  97
#define QTLS_ECDHE_P384_SHARED_SECRET_BYTES 48

/*
 * Forward declarations
 */
typedef struct qtls_ctx_st QTLS_CTX;
typedef struct qtls_connection_st QTLS_CONNECTION;
typedef struct qtls_x509_st QTLS_X509;

/*
 * KYBER1024 key structure
 * Used for post-quantum key encapsulation
 */
typedef struct {
    uint8_t public_key[QTLS_KYBER1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[QTLS_KYBER1024_SECRET_KEY_BYTES];
    uint8_t ciphertext[QTLS_KYBER1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret[QTLS_KYBER1024_SHARED_SECRET_BYTES];
    int has_secret_key;    /* 1 if secret key is present */
    int has_shared_secret; /* 1 if shared secret is derived */
} QTLS_KYBER_KEY;

/*
 * DILITHIUM3 key structure
 * Used for post-quantum digital signatures
 */
typedef struct {
    uint8_t public_key[QTLS_DILITHIUM3_PUBLIC_KEY_BYTES];
    uint8_t secret_key[QTLS_DILITHIUM3_SECRET_KEY_BYTES];
    int has_secret_key;    /* 1 if secret key is present */
} QTLS_DILITHIUM_KEY;

/*
 * ECDHE P-384 key structure
 * Used for classical key exchange
 */
typedef struct {
    uint8_t public_key[QTLS_ECDHE_P384_PUBLIC_KEY_BYTES];
    uint8_t shared_secret[QTLS_ECDHE_P384_SHARED_SECRET_BYTES];
    void *evp_pkey;        /* OpenSSL EVP_PKEY pointer */
    int has_shared_secret; /* 1 if shared secret is derived */
} QTLS_ECDHE_KEY;

/*
 * Hybrid master secret
 * Combines classical and PQC shared secrets
 */
typedef struct {
    uint8_t classical_secret[QTLS_ECDHE_P384_SHARED_SECRET_BYTES];
    uint8_t pqc_secret[QTLS_KYBER1024_SHARED_SECRET_BYTES];
    uint8_t master_secret[QTLS_MAX_MASTER_SECRET];
    uint8_t client_random[QTLS_MAX_RANDOM_LEN];
    uint8_t server_random[QTLS_MAX_RANDOM_LEN];
} QTLS_HYBRID_SECRET;

/*
 * Session keys derived from master secret
 */
typedef struct {
    uint8_t client_write_key[32];
    uint8_t server_write_key[32];
    uint8_t client_write_iv[12];
    uint8_t server_write_iv[12];
} QTLS_SESSION_KEYS;

/*
 * Certificate structure
 */
typedef struct {
    uint8_t *data;
    size_t length;
    int format; /* QTLS_FILETYPE_PEM or QTLS_FILETYPE_ASN1 */
    void *x509; /* OpenSSL X509 pointer */
    QTLS_DILITHIUM_KEY *dilithium_key;
    int verified;
} QTLS_CERTIFICATE;

/*
 * HSM configuration for PKCS#11
 */
typedef struct {
    char *pkcs11_module_path;  /* Path to PKCS#11 library */
    char *token_label;         /* HSM token label */
    char *pin;                 /* HSM PIN (stored securely) */
    void *pkcs11_handle;       /* dlopen handle */
    void *function_list;       /* CK_FUNCTION_LIST pointer */
    unsigned long session;     /* CK_SESSION_HANDLE */
    int initialized;           /* 1 if HSM is initialized */
} QTLS_HSM_CONFIG;

/*
 * Callback function types
 */
typedef int (*qtls_verify_callback)(int preverify_ok, QTLS_X509 *x509_ctx);
typedef int (*qtls_psk_callback)(QTLS_CONNECTION *conn, const char *hint,
                                  char *identity, unsigned int max_identity_len,
                                  unsigned char *psk, unsigned int max_psk_len);

/******************************************************************************
 * Context Management Functions
 ******************************************************************************/

/*
 * Create a new Q-TLS context
 * mode: QTLS_CLIENT_MODE or QTLS_SERVER_MODE
 * Returns: New context or NULL on error
 */
QTLS_CTX *qtls_ctx_new(int mode);

/*
 * Free a Q-TLS context
 */
void qtls_ctx_free(QTLS_CTX *ctx);

/*
 * Set options on context
 * options: Bitmask of QTLS_OP_* flags
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_ctx_set_options(QTLS_CTX *ctx, uint32_t options);

/*
 * Get current options
 * Returns: Current option flags
 */
uint32_t qtls_ctx_get_options(QTLS_CTX *ctx);

/*
 * Set verification mode
 * mode: QTLS_VERIFY_* flags
 * callback: Optional verification callback
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_ctx_set_verify_mode(QTLS_CTX *ctx, int mode, qtls_verify_callback callback);

/*
 * Load certificate from file
 * file: Path to certificate file
 * type: QTLS_FILETYPE_PEM or QTLS_FILETYPE_ASN1
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_ctx_use_certificate_file(QTLS_CTX *ctx, const char *file, int type);

/*
 * Load private key from file
 * file: Path to private key file
 * type: QTLS_FILETYPE_PEM or QTLS_FILETYPE_ASN1
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_ctx_use_private_key_file(QTLS_CTX *ctx, const char *file, int type);

/*
 * Load private key from HSM using PKCS#11 URI
 * uri: PKCS#11 URI (e.g., "pkcs11:token=luna;object=mykey")
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_ctx_use_hsm_key(QTLS_CTX *ctx, const char *uri);

/*
 * Load CA certificates for verification
 * file: Path to CA bundle file (can be NULL)
 * path: Path to CA directory (can be NULL)
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_ctx_load_verify_locations(QTLS_CTX *ctx, const char *file, const char *path);

/*
 * Set supported PQC algorithms
 * kems: Array of KEM algorithm IDs
 * num_kems: Number of KEMs in array
 * sigs: Array of signature algorithm IDs
 * num_sigs: Number of signatures in array
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_ctx_set_pqc_algorithms(QTLS_CTX *ctx,
                                 const uint16_t *kems, size_t num_kems,
                                 const uint16_t *sigs, size_t num_sigs);

/******************************************************************************
 * Connection Management Functions
 ******************************************************************************/

/*
 * Create a new Q-TLS connection
 * ctx: Q-TLS context
 * Returns: New connection or NULL on error
 */
QTLS_CONNECTION *qtls_new(QTLS_CTX *ctx);

/*
 * Free a Q-TLS connection
 */
void qtls_free(QTLS_CONNECTION *conn);

/*
 * Associate file descriptor with connection
 * fd: Socket file descriptor
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_set_fd(QTLS_CONNECTION *conn, int fd);

/*
 * Get file descriptor
 * Returns: File descriptor or -1
 */
int qtls_get_fd(QTLS_CONNECTION *conn);

/******************************************************************************
 * Handshake Functions
 ******************************************************************************/

/*
 * Perform client-side handshake
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_connect(QTLS_CONNECTION *conn);

/*
 * Perform server-side handshake
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_accept(QTLS_CONNECTION *conn);

/*
 * Set server name indication (SNI) for client
 * hostname: Server hostname
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_set_server_name(QTLS_CONNECTION *conn, const char *hostname);

/*
 * Verify peer certificate
 * Returns: 1 if verified, 0 if not verified or error
 */
int qtls_verify_peer_certificate(QTLS_CONNECTION *conn);

/******************************************************************************
 * I/O Functions
 ******************************************************************************/

/*
 * Read encrypted data from connection
 * buf: Buffer to store data
 * num: Maximum bytes to read
 * Returns: Number of bytes read, or error code
 */
int qtls_read(QTLS_CONNECTION *conn, void *buf, int num);

/*
 * Write encrypted data to connection
 * buf: Data to write
 * num: Number of bytes to write
 * Returns: Number of bytes written, or error code
 */
int qtls_write(QTLS_CONNECTION *conn, const void *buf, int num);

/*
 * Get number of bytes pending
 * Returns: Number of bytes available to read
 */
int qtls_pending(QTLS_CONNECTION *conn);

/*
 * Shutdown connection
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_shutdown(QTLS_CONNECTION *conn);

/******************************************************************************
 * Cryptographic Functions
 ******************************************************************************/

/*
 * Generate KYBER1024 keypair
 * key: KYBER key structure to populate
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_kyber_keygen(QTLS_KYBER_KEY *key);

/*
 * KYBER1024 encapsulation (client side)
 * key: KYBER key structure with public key
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_kyber_encapsulate(QTLS_KYBER_KEY *key);

/*
 * KYBER1024 decapsulation (server side)
 * key: KYBER key structure with secret key and ciphertext
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_kyber_decapsulate(QTLS_KYBER_KEY *key);

/*
 * Generate DILITHIUM3 keypair
 * key: DILITHIUM key structure to populate
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_dilithium_keygen(QTLS_DILITHIUM_KEY *key);

/*
 * DILITHIUM3 sign message
 * key: DILITHIUM key structure with secret key
 * msg: Message to sign
 * msg_len: Length of message
 * sig: Buffer for signature
 * sig_len: Output signature length
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_dilithium_sign(const QTLS_DILITHIUM_KEY *key,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t *sig, size_t *sig_len);

/*
 * DILITHIUM3 verify signature
 * key: DILITHIUM key structure with public key
 * msg: Message that was signed
 * msg_len: Length of message
 * sig: Signature to verify
 * sig_len: Length of signature
 * Returns: 1 if valid, 0 if invalid, negative on error
 */
int qtls_dilithium_verify(const QTLS_DILITHIUM_KEY *key,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len);

/*
 * Derive hybrid master secret
 * secret: Hybrid secret structure to populate
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_derive_master_secret(QTLS_HYBRID_SECRET *secret);

/*
 * Derive session keys from master secret
 * secret: Hybrid secret structure
 * keys: Session keys structure to populate
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_derive_session_keys(const QTLS_HYBRID_SECRET *secret,
                              QTLS_SESSION_KEYS *keys);

/******************************************************************************
 * HSM Functions (Luna HSM via PKCS#11)
 ******************************************************************************/

/*
 * Initialize HSM connection
 * module_path: Path to PKCS#11 library
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_hsm_init(const char *module_path);

/*
 * Login to HSM
 * token_label: HSM token label
 * pin: User PIN
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_hsm_login(const char *token_label, const char *pin);

/*
 * Generate ephemeral key in HSM
 * conn: Q-TLS connection
 * algorithm: QTLS_KEM_KYBER1024 or QTLS_SIG_DILITHIUM3
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_generate_ephemeral_key_hsm(QTLS_CONNECTION *conn, uint16_t algorithm);

/*
 * Perform KYBER decapsulation in HSM
 * conn: Q-TLS connection
 * ciphertext: KYBER ciphertext
 * ct_len: Length of ciphertext
 * shared_secret: Output buffer for shared secret
 * Returns: QTLS_SUCCESS or error code
 */
int qtls_hsm_kyber_decapsulate(QTLS_CONNECTION *conn,
                                const uint8_t *ciphertext, size_t ct_len,
                                uint8_t *shared_secret);

/*
 * Cleanup HSM connection
 */
void qtls_hsm_cleanup(void);

/******************************************************************************
 * Utility Functions
 ******************************************************************************/

/*
 * Get error string for error code
 * error: Error code
 * Returns: Human-readable error string
 */
const char *qtls_get_error_string(int error);

/*
 * Get last error for connection
 * conn: Q-TLS connection
 * Returns: Last error code
 */
int qtls_get_error(QTLS_CONNECTION *conn);

/*
 * Get library version string
 * Returns: Version string (e.g., "1.0.0")
 */
const char *qtls_version(void);

/*
 * Get negotiated cipher suite
 * conn: Q-TLS connection
 * Returns: Cipher suite string or NULL
 */
const char *qtls_get_cipher(QTLS_CONNECTION *conn);

/*
 * Get negotiated protocol version
 * conn: Q-TLS connection
 * Returns: Protocol version (e.g., QTLS_VERSION_1_3)
 */
int qtls_get_version(QTLS_CONNECTION *conn);

/*
 * Get peer certificate
 * conn: Q-TLS connection
 * Returns: Certificate or NULL
 */
QTLS_CERTIFICATE *qtls_get_peer_certificate(QTLS_CONNECTION *conn);

/*
 * Free certificate
 */
void qtls_certificate_free(QTLS_CERTIFICATE *cert);

/*
 * Secure memory zeroing (constant-time)
 * ptr: Memory to zero
 * len: Length of memory
 */
void qtls_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* QTLS_H */
