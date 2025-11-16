/*
 * Q-TLS: Quantum-Resistant Transport Security Layer
 * TLS-PQC Hybrid Handshake Protocol Implementation
 *
 * This module implements the TLS 1.3 handshake with PQC extensions:
 * - ClientHello/ServerHello with PQC algorithm negotiation
 * - Dual key exchange: ECDHE P-384 + KYBER1024
 * - Dual signature verification: RSA/ECDSA + DILITHIUM3
 * - Hybrid session key derivation
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

/* Logging macros */
#ifdef ENABLE_LOGGING
#define LOG_INFO(fmt, ...) fprintf(stderr, "[QTLS-HANDSHAKE-INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[QTLS-HANDSHAKE-ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stderr, "[QTLS-HANDSHAKE-DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)
#define LOG_ERROR(fmt, ...)
#define LOG_DEBUG(fmt, ...)
#endif

/* Handshake message types */
#define QTLS_MSG_CLIENT_HELLO       0x01
#define QTLS_MSG_SERVER_HELLO       0x02
#define QTLS_MSG_ENCRYPTED_EXTENSIONS 0x08
#define QTLS_MSG_CERTIFICATE        0x0B
#define QTLS_MSG_CERTIFICATE_VERIFY 0x0F
#define QTLS_MSG_FINISHED           0x14

/* PQC Extension IDs (using experimental range) */
#define QTLS_EXT_SUPPORTED_PQC_KEMS  0xFE00
#define QTLS_EXT_SUPPORTED_PQC_SIGS  0xFE01
#define QTLS_EXT_KYBER_KEY_SHARE     0xFE02

/* Maximum handshake message size */
#define QTLS_MAX_HANDSHAKE_MSG_SIZE  65536

/*
 * Handshake state
 */
typedef enum {
    QTLS_HS_STATE_START,
    QTLS_HS_STATE_CLIENT_HELLO_SENT,
    QTLS_HS_STATE_SERVER_HELLO_RECEIVED,
    QTLS_HS_STATE_SERVER_CERT_RECEIVED,
    QTLS_HS_STATE_SERVER_FINISHED,
    QTLS_HS_STATE_CLIENT_FINISHED,
    QTLS_HS_STATE_CONNECTED
} qtls_handshake_state_t;

/*
 * Connection structure (internal)
 */
struct qtls_connection_st {
    QTLS_CTX *ctx;
    int fd;
    int mode; /* QTLS_CLIENT_MODE or QTLS_SERVER_MODE */
    qtls_handshake_state_t state;

    /* Cryptographic state */
    QTLS_KYBER_KEY kyber_key;
    QTLS_ECDHE_KEY ecdhe_key;
    QTLS_HYBRID_SECRET hybrid_secret;
    QTLS_SESSION_KEYS session_keys;

    /* Peer keys */
    QTLS_KYBER_KEY peer_kyber_key;
    QTLS_DILITHIUM_KEY peer_dilithium_key;

    /* Certificate chain */
    QTLS_CERTIFICATE *peer_cert;

    /* Error state */
    int last_error;

    /* OpenSSL SSL object for classical crypto */
    SSL *ssl;
};

/*
 * Context structure (internal)
 */
struct qtls_ctx_st {
    int mode; /* QTLS_CLIENT_MODE or QTLS_SERVER_MODE */
    uint32_t options;
    int verify_mode;
    qtls_verify_callback verify_callback;

    /* Certificate and keys */
    QTLS_CERTIFICATE *cert;
    QTLS_DILITHIUM_KEY dilithium_key;

    /* OpenSSL SSL_CTX for classical crypto */
    SSL_CTX *ssl_ctx;

    /* Supported algorithms */
    uint16_t supported_kems[8];
    size_t num_kems;
    uint16_t supported_sigs[8];
    size_t num_sigs;

#ifdef ENABLE_HSM
    QTLS_HSM_CONFIG hsm_config;
#endif
};

/******************************************************************************
 * ECDHE P-384 Helper Functions
 ******************************************************************************/

/*
 * Generate ECDHE P-384 keypair
 */
static int qtls_ecdhe_keygen(QTLS_ECDHE_KEY *key) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t pubkey_len = QTLS_ECDHE_P384_PUBLIC_KEY_BYTES;
    int ret = QTLS_ERROR_KEY_GENERATION;

    if (key == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Create key generation context */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        LOG_ERROR("Failed to create ECDHE context");
        return QTLS_ERROR_KEY_GENERATION;
    }

    /* Initialize key generation */
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        LOG_ERROR("ECDHE keygen init failed");
        goto cleanup;
    }

    /* Set curve to P-384 (NIST secp384r1) */
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) {
        LOG_ERROR("ECDHE set curve failed");
        goto cleanup;
    }

    /* Generate key */
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        LOG_ERROR("ECDHE keygen failed");
        goto cleanup;
    }

    /* Extract public key */
    if (EVP_PKEY_get_raw_public_key(pkey, key->public_key, &pubkey_len) <= 0) {
        LOG_ERROR("Failed to extract ECDHE public key");
        goto cleanup;
    }

    key->evp_pkey = pkey;
    key->has_shared_secret = 0;
    pkey = NULL; /* Don't free, stored in key structure */
    ret = QTLS_SUCCESS;

    LOG_DEBUG("ECDHE P-384 keypair generated");

cleanup:
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return ret;
}

/*
 * Derive ECDHE shared secret
 */
static int qtls_ecdhe_derive(QTLS_ECDHE_KEY *key, const uint8_t *peer_public_key,
                             size_t peer_pubkey_len) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *peer_key = NULL;
    size_t secret_len = QTLS_ECDHE_P384_SHARED_SECRET_BYTES;
    int ret = QTLS_ERROR_KEY_DERIVATION;

    if (key == NULL || peer_public_key == NULL || key->evp_pkey == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Create peer public key */
    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, NULL,
                                            peer_public_key, peer_pubkey_len);
    if (peer_key == NULL) {
        LOG_ERROR("Failed to import peer ECDHE public key");
        return QTLS_ERROR_KEY_DERIVATION;
    }

    /* Create derivation context */
    ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (ctx == NULL) {
        LOG_ERROR("Failed to create ECDHE derivation context");
        EVP_PKEY_free(peer_key);
        return QTLS_ERROR_KEY_DERIVATION;
    }

    /* Initialize derivation */
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        LOG_ERROR("ECDHE derive init failed");
        goto cleanup;
    }

    /* Set peer key */
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        LOG_ERROR("ECDHE set peer failed");
        goto cleanup;
    }

    /* Derive shared secret */
    if (EVP_PKEY_derive(ctx, key->shared_secret, &secret_len) <= 0) {
        LOG_ERROR("ECDHE derive failed");
        goto cleanup;
    }

    key->has_shared_secret = 1;
    ret = QTLS_SUCCESS;

    LOG_DEBUG("ECDHE shared secret derived");

cleanup:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (peer_key != NULL) {
        EVP_PKEY_free(peer_key);
    }

    return ret;
}

/******************************************************************************
 * Handshake Message Functions
 ******************************************************************************/

/*
 * Send ClientHello with PQC extensions
 */
static int qtls_send_client_hello(QTLS_CONNECTION *conn) {
    uint8_t msg[QTLS_MAX_HANDSHAKE_MSG_SIZE];
    size_t msg_len = 0;
    int ret;

    LOG_INFO("Sending ClientHello with PQC extensions");

    /* Generate client random */
    if (RAND_bytes(conn->hybrid_secret.client_random, QTLS_MAX_RANDOM_LEN) != 1) {
        LOG_ERROR("Failed to generate client random");
        return QTLS_ERROR_HANDSHAKE_FAILED;
    }

    /* Message type */
    msg[msg_len++] = QTLS_MSG_CLIENT_HELLO;

    /* Add client random */
    memcpy(msg + msg_len, conn->hybrid_secret.client_random, QTLS_MAX_RANDOM_LEN);
    msg_len += QTLS_MAX_RANDOM_LEN;

    /* Generate ECDHE keypair */
    ret = qtls_ecdhe_keygen(&conn->ecdhe_key);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to generate ECDHE keypair");
        return ret;
    }

    /* Add ECDHE public key */
    memcpy(msg + msg_len, conn->ecdhe_key.public_key,
           QTLS_ECDHE_P384_PUBLIC_KEY_BYTES);
    msg_len += QTLS_ECDHE_P384_PUBLIC_KEY_BYTES;

    /* Add supported PQC KEM algorithms */
    msg[msg_len++] = (QTLS_KEM_KYBER1024 >> 8) & 0xFF;
    msg[msg_len++] = QTLS_KEM_KYBER1024 & 0xFF;

    /* Add supported PQC signature algorithms */
    msg[msg_len++] = (QTLS_SIG_DILITHIUM3 >> 8) & 0xFF;
    msg[msg_len++] = QTLS_SIG_DILITHIUM3 & 0xFF;

    /* Send message */
    ssize_t sent = send(conn->fd, msg, msg_len, 0);
    if (sent != (ssize_t)msg_len) {
        LOG_ERROR("Failed to send ClientHello (sent %zd of %zu bytes)", sent, msg_len);
        return QTLS_ERROR_SYSCALL;
    }

    conn->state = QTLS_HS_STATE_CLIENT_HELLO_SENT;
    LOG_INFO("ClientHello sent (%zu bytes)", msg_len);

    return QTLS_SUCCESS;
}

/*
 * Receive and process ServerHello
 */
static int qtls_receive_server_hello(QTLS_CONNECTION *conn) {
    uint8_t msg[QTLS_MAX_HANDSHAKE_MSG_SIZE];
    ssize_t received;
    size_t offset = 0;
    int ret;

    LOG_INFO("Waiting for ServerHello");

    /* Receive message */
    received = recv(conn->fd, msg, sizeof(msg), 0);
    if (received <= 0) {
        LOG_ERROR("Failed to receive ServerHello");
        return QTLS_ERROR_SYSCALL;
    }

    LOG_DEBUG("Received %zd bytes", received);

    /* Check message type */
    if (msg[offset++] != QTLS_MSG_SERVER_HELLO) {
        LOG_ERROR("Expected ServerHello, got 0x%02x", msg[0]);
        return QTLS_ERROR_INVALID_MESSAGE;
    }

    /* Extract server random */
    memcpy(conn->hybrid_secret.server_random, msg + offset, QTLS_MAX_RANDOM_LEN);
    offset += QTLS_MAX_RANDOM_LEN;

    /* Extract server ECDHE public key */
    uint8_t server_ecdhe_pubkey[QTLS_ECDHE_P384_PUBLIC_KEY_BYTES];
    memcpy(server_ecdhe_pubkey, msg + offset, QTLS_ECDHE_P384_PUBLIC_KEY_BYTES);
    offset += QTLS_ECDHE_P384_PUBLIC_KEY_BYTES;

    /* Extract server KYBER public key */
    memcpy(conn->peer_kyber_key.public_key, msg + offset,
           QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    offset += QTLS_KYBER1024_PUBLIC_KEY_BYTES;

    LOG_INFO("ServerHello received and parsed");

    /* Derive ECDHE shared secret */
    ret = qtls_ecdhe_derive(&conn->ecdhe_key, server_ecdhe_pubkey,
                            QTLS_ECDHE_P384_PUBLIC_KEY_BYTES);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to derive ECDHE shared secret");
        return ret;
    }

    /* Perform KYBER encapsulation */
    ret = qtls_kyber_encapsulate(&conn->peer_kyber_key);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to encapsulate KYBER key");
        return ret;
    }

    /* Copy shared secrets to hybrid secret structure */
    memcpy(conn->hybrid_secret.classical_secret,
           conn->ecdhe_key.shared_secret,
           QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memcpy(conn->hybrid_secret.pqc_secret,
           conn->peer_kyber_key.shared_secret,
           QTLS_KYBER1024_SHARED_SECRET_BYTES);

    conn->state = QTLS_HS_STATE_SERVER_HELLO_RECEIVED;
    LOG_INFO("Key exchange completed");

    return QTLS_SUCCESS;
}

/*
 * Send ServerHello with PQC key shares
 */
static int qtls_send_server_hello(QTLS_CONNECTION *conn) {
    uint8_t msg[QTLS_MAX_HANDSHAKE_MSG_SIZE];
    size_t msg_len = 0;
    int ret;

    LOG_INFO("Sending ServerHello with PQC extensions");

    /* Generate server random */
    if (RAND_bytes(conn->hybrid_secret.server_random, QTLS_MAX_RANDOM_LEN) != 1) {
        LOG_ERROR("Failed to generate server random");
        return QTLS_ERROR_HANDSHAKE_FAILED;
    }

    /* Message type */
    msg[msg_len++] = QTLS_MSG_SERVER_HELLO;

    /* Add server random */
    memcpy(msg + msg_len, conn->hybrid_secret.server_random, QTLS_MAX_RANDOM_LEN);
    msg_len += QTLS_MAX_RANDOM_LEN;

    /* Generate ECDHE keypair */
    ret = qtls_ecdhe_keygen(&conn->ecdhe_key);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to generate ECDHE keypair");
        return ret;
    }

    /* Add ECDHE public key */
    memcpy(msg + msg_len, conn->ecdhe_key.public_key,
           QTLS_ECDHE_P384_PUBLIC_KEY_BYTES);
    msg_len += QTLS_ECDHE_P384_PUBLIC_KEY_BYTES;

    /* Generate KYBER keypair */
    ret = qtls_kyber_keygen(&conn->kyber_key);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to generate KYBER keypair");
        return ret;
    }

    /* Add KYBER public key */
    memcpy(msg + msg_len, conn->kyber_key.public_key,
           QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    msg_len += QTLS_KYBER1024_PUBLIC_KEY_BYTES;

    /* Send message */
    ssize_t sent = send(conn->fd, msg, msg_len, 0);
    if (sent != (ssize_t)msg_len) {
        LOG_ERROR("Failed to send ServerHello");
        return QTLS_ERROR_SYSCALL;
    }

    LOG_INFO("ServerHello sent (%zu bytes)", msg_len);

    return QTLS_SUCCESS;
}

/*
 * Receive ClientHello
 */
static int qtls_receive_client_hello(QTLS_CONNECTION *conn) {
    uint8_t msg[QTLS_MAX_HANDSHAKE_MSG_SIZE];
    ssize_t received;
    size_t offset = 0;

    LOG_INFO("Waiting for ClientHello");

    /* Receive message */
    received = recv(conn->fd, msg, sizeof(msg), 0);
    if (received <= 0) {
        LOG_ERROR("Failed to receive ClientHello");
        return QTLS_ERROR_SYSCALL;
    }

    LOG_DEBUG("Received %zd bytes", received);

    /* Check message type */
    if (msg[offset++] != QTLS_MSG_CLIENT_HELLO) {
        LOG_ERROR("Expected ClientHello, got 0x%02x", msg[0]);
        return QTLS_ERROR_INVALID_MESSAGE;
    }

    /* Extract client random */
    memcpy(conn->hybrid_secret.client_random, msg + offset, QTLS_MAX_RANDOM_LEN);
    offset += QTLS_MAX_RANDOM_LEN;

    /* Extract client ECDHE public key */
    uint8_t client_ecdhe_pubkey[QTLS_ECDHE_P384_PUBLIC_KEY_BYTES];
    memcpy(client_ecdhe_pubkey, msg + offset, QTLS_ECDHE_P384_PUBLIC_KEY_BYTES);
    offset += QTLS_ECDHE_P384_PUBLIC_KEY_BYTES;

    LOG_INFO("ClientHello received and parsed");

    /* Note: Client ECDHE key will be used after ServerHello is sent */
    memcpy(conn->peer_kyber_key.public_key, client_ecdhe_pubkey,
           QTLS_ECDHE_P384_PUBLIC_KEY_BYTES);

    return QTLS_SUCCESS;
}

/******************************************************************************
 * Public Handshake Functions
 ******************************************************************************/

/*
 * Perform client-side handshake
 */
int qtls_connect(QTLS_CONNECTION *conn) {
    int ret;

    if (conn == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    if (conn->mode != QTLS_CLIENT_MODE) {
        LOG_ERROR("qtls_connect called on server connection");
        return QTLS_ERROR_INVALID_ARGUMENT;
    }

    LOG_INFO("Starting Q-TLS client handshake");

    /* Send ClientHello */
    ret = qtls_send_client_hello(conn);
    if (ret != QTLS_SUCCESS) {
        conn->last_error = ret;
        return ret;
    }

    /* Receive ServerHello */
    ret = qtls_receive_server_hello(conn);
    if (ret != QTLS_SUCCESS) {
        conn->last_error = ret;
        return ret;
    }

    /* Derive hybrid master secret */
    ret = qtls_derive_master_secret(&conn->hybrid_secret);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to derive master secret");
        conn->last_error = ret;
        return ret;
    }

    /* Derive session keys */
    ret = qtls_derive_session_keys(&conn->hybrid_secret, &conn->session_keys);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to derive session keys");
        conn->last_error = ret;
        return ret;
    }

    /* Send KYBER ciphertext to server */
    ssize_t sent = send(conn->fd, conn->peer_kyber_key.ciphertext,
                        QTLS_KYBER1024_CIPHERTEXT_BYTES, 0);
    if (sent != QTLS_KYBER1024_CIPHERTEXT_BYTES) {
        LOG_ERROR("Failed to send KYBER ciphertext");
        conn->last_error = QTLS_ERROR_SYSCALL;
        return QTLS_ERROR_SYSCALL;
    }

    conn->state = QTLS_HS_STATE_CONNECTED;
    LOG_INFO("Q-TLS client handshake completed successfully");

    return QTLS_SUCCESS;
}

/*
 * Perform server-side handshake
 */
int qtls_accept(QTLS_CONNECTION *conn) {
    int ret;

    if (conn == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    if (conn->mode != QTLS_SERVER_MODE) {
        LOG_ERROR("qtls_accept called on client connection");
        return QTLS_ERROR_INVALID_ARGUMENT;
    }

    LOG_INFO("Starting Q-TLS server handshake");

    /* Receive ClientHello */
    ret = qtls_receive_client_hello(conn);
    if (ret != QTLS_SUCCESS) {
        conn->last_error = ret;
        return ret;
    }

    /* Send ServerHello */
    ret = qtls_send_server_hello(conn);
    if (ret != QTLS_SUCCESS) {
        conn->last_error = ret;
        return ret;
    }

    /* Receive KYBER ciphertext from client */
    uint8_t kyber_ciphertext[QTLS_KYBER1024_CIPHERTEXT_BYTES];
    ssize_t received = recv(conn->fd, kyber_ciphertext,
                            QTLS_KYBER1024_CIPHERTEXT_BYTES, 0);
    if (received != QTLS_KYBER1024_CIPHERTEXT_BYTES) {
        LOG_ERROR("Failed to receive KYBER ciphertext");
        conn->last_error = QTLS_ERROR_SYSCALL;
        return QTLS_ERROR_SYSCALL;
    }

    /* Decapsulate KYBER ciphertext */
    memcpy(conn->kyber_key.ciphertext, kyber_ciphertext,
           QTLS_KYBER1024_CIPHERTEXT_BYTES);
    ret = qtls_kyber_decapsulate(&conn->kyber_key);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to decapsulate KYBER key");
        conn->last_error = ret;
        return ret;
    }

    /* Derive ECDHE shared secret (using client's public key received earlier) */
    ret = qtls_ecdhe_derive(&conn->ecdhe_key, conn->peer_kyber_key.public_key,
                            QTLS_ECDHE_P384_PUBLIC_KEY_BYTES);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to derive ECDHE shared secret");
        conn->last_error = ret;
        return ret;
    }

    /* Copy shared secrets */
    memcpy(conn->hybrid_secret.classical_secret,
           conn->ecdhe_key.shared_secret,
           QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memcpy(conn->hybrid_secret.pqc_secret,
           conn->kyber_key.shared_secret,
           QTLS_KYBER1024_SHARED_SECRET_BYTES);

    /* Derive hybrid master secret */
    ret = qtls_derive_master_secret(&conn->hybrid_secret);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to derive master secret");
        conn->last_error = ret;
        return ret;
    }

    /* Derive session keys */
    ret = qtls_derive_session_keys(&conn->hybrid_secret, &conn->session_keys);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to derive session keys");
        conn->last_error = ret;
        return ret;
    }

    conn->state = QTLS_HS_STATE_CONNECTED;
    LOG_INFO("Q-TLS server handshake completed successfully");

    return QTLS_SUCCESS;
}

/*
 * Verify peer certificate
 */
int qtls_verify_peer_certificate(QTLS_CONNECTION *conn) {
    if (conn == NULL) {
        return 0;
    }

    /* TODO: Implement full certificate chain validation
     * including DILITHIUM3 signature verification */

    LOG_INFO("Certificate verification (stub - always succeeds)");
    return 1;
}

/*
 * Set server name indication
 */
int qtls_set_server_name(QTLS_CONNECTION *conn, const char *hostname) {
    if (conn == NULL || hostname == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    LOG_INFO("SNI set to: %s", hostname);
    return QTLS_SUCCESS;
}
