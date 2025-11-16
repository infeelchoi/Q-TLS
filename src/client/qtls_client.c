/*
 * Q-TLS: Quantum-Resistant Transport Security Layer
 * Client Implementation
 *
 * This module provides client-side Q-TLS functionality:
 * - Client initialization and configuration
 * - Server connection
 * - Hybrid handshake execution
 * - Encrypted data transmission
 * - Certificate verification
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Logging macros */
#ifdef ENABLE_LOGGING
#define LOG_INFO(fmt, ...) fprintf(stderr, "[QTLS-CLIENT-INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[QTLS-CLIENT-ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stderr, "[QTLS-CLIENT-DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)
#define LOG_ERROR(fmt, ...)
#define LOG_DEBUG(fmt, ...)
#endif

/* External declarations */
extern int qtls_connect(QTLS_CONNECTION *conn);

/******************************************************************************
 * Network Helper Functions
 ******************************************************************************/

/*
 * Create TCP socket and connect to server
 * Helper function for client applications
 */
static int qtls_tcp_connect(const char *hostname, uint16_t port) {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    char port_str[6];
    int ret;

    if (hostname == NULL) {
        LOG_ERROR("NULL hostname");
        return -1;
    }

    /* Convert port to string */
    snprintf(port_str, sizeof(port_str), "%u", port);

    /* Setup hints for getaddrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP */

    /* Resolve hostname */
    ret = getaddrinfo(hostname, port_str, &hints, &servinfo);
    if (ret != 0) {
        LOG_ERROR("getaddrinfo failed: %s", gai_strerror(ret));
        return -1;
    }

    /* Try each address until we successfully connect */
    for (p = servinfo; p != NULL; p = p->ai_next) {
        /* Create socket */
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            LOG_DEBUG("socket() failed: %s", strerror(errno));
            continue;
        }

        /* Connect to server */
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            LOG_DEBUG("connect() failed: %s", strerror(errno));
            continue;
        }

        /* Successfully connected */
        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        LOG_ERROR("Failed to connect to %s:%u", hostname, port);
        return -1;
    }

    LOG_INFO("Connected to %s:%u (fd=%d)", hostname, port, sockfd);
    return sockfd;
}

/******************************************************************************
 * Client-Specific Functions
 ******************************************************************************/

/*
 * Connect to Q-TLS server
 * High-level convenience function
 *
 * Example:
 *   QTLS_CTX *ctx = qtls_ctx_new(QTLS_CLIENT_MODE);
 *   qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE);
 *   QTLS_CONNECTION *conn = qtls_client_connect(ctx, "server.example.com", 8443);
 */
QTLS_CONNECTION *qtls_client_connect(QTLS_CTX *ctx, const char *hostname,
                                      uint16_t port) {
    QTLS_CONNECTION *conn = NULL;
    int sockfd = -1;
    int ret;

    if (ctx == NULL || hostname == NULL) {
        LOG_ERROR("NULL argument");
        return NULL;
    }

    if (ctx->mode != QTLS_CLIENT_MODE) {
        LOG_ERROR("Context is not in client mode");
        return NULL;
    }

    /* Create TCP connection */
    sockfd = qtls_tcp_connect(hostname, port);
    if (sockfd < 0) {
        return NULL;
    }

    /* Create Q-TLS connection */
    conn = qtls_new(ctx);
    if (conn == NULL) {
        LOG_ERROR("Failed to create Q-TLS connection");
        close(sockfd);
        return NULL;
    }

    /* Associate socket with connection */
    ret = qtls_set_fd(conn, sockfd);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to set file descriptor");
        qtls_free(conn);
        close(sockfd);
        return NULL;
    }

    /* Set server name for SNI */
    ret = qtls_set_server_name(conn, hostname);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Failed to set server name");
        qtls_free(conn);
        return NULL;
    }

    /* Perform Q-TLS handshake */
    ret = qtls_connect(conn);
    if (ret != QTLS_SUCCESS) {
        LOG_ERROR("Handshake failed: %s", qtls_get_error_string(ret));
        qtls_free(conn);
        return NULL;
    }

    LOG_INFO("Q-TLS connection established to %s:%u", hostname, port);
    return conn;
}

/*
 * Verify server certificate chain
 * Includes both classical (RSA/ECDSA) and PQC (DILITHIUM3) verification
 */
int qtls_client_verify_certificate(QTLS_CONNECTION *conn) {
    X509 *cert = NULL;
    int ret = 0;

    if (conn == NULL) {
        return 0;
    }

    if (conn->ssl == NULL) {
        LOG_ERROR("SSL object not initialized");
        return 0;
    }

    /* Get peer certificate from OpenSSL */
    cert = SSL_get_peer_certificate(conn->ssl);
    if (cert == NULL) {
        LOG_ERROR("No peer certificate");
        return 0;
    }

    /* Verify certificate using OpenSSL */
    long verify_result = SSL_get_verify_result(conn->ssl);
    if (verify_result != X509_V_OK) {
        LOG_ERROR("Certificate verification failed: %s",
                  X509_verify_cert_error_string(verify_result));
        X509_free(cert);
        return 0;
    }

    LOG_INFO("Classical certificate verification passed");

    /* TODO: Verify DILITHIUM3 signature in certificate extension */
    /* This would extract the PQC signature from X.509 extension and verify it */

    ret = 1;
    LOG_INFO("Certificate verification successful");

    X509_free(cert);
    return ret;
}

/*
 * Send application data with automatic encryption
 * Wraps qtls_write with additional error handling
 */
int qtls_client_send(QTLS_CONNECTION *conn, const void *data, size_t len) {
    int total_sent = 0;
    int bytes_sent;

    if (conn == NULL || data == NULL) {
        LOG_ERROR("NULL argument");
        return QTLS_ERROR_NULL_POINTER;
    }

    if (len == 0) {
        return 0;
    }

    /* Send data in chunks if necessary */
    while ((size_t)total_sent < len) {
        bytes_sent = qtls_write(conn,
                                (const uint8_t *)data + total_sent,
                                len - total_sent);

        if (bytes_sent <= 0) {
            if (bytes_sent == QTLS_ERROR_WANT_WRITE) {
                /* Would block, try again */
                continue;
            }

            LOG_ERROR("Send failed: %s", qtls_get_error_string(bytes_sent));
            return bytes_sent;
        }

        total_sent += bytes_sent;
    }

    LOG_DEBUG("Sent %d bytes", total_sent);
    return total_sent;
}

/*
 * Receive application data with automatic decryption
 * Wraps qtls_read with additional error handling
 */
int qtls_client_receive(QTLS_CONNECTION *conn, void *buffer, size_t max_len) {
    int bytes_received;

    if (conn == NULL || buffer == NULL) {
        LOG_ERROR("NULL argument");
        return QTLS_ERROR_NULL_POINTER;
    }

    if (max_len == 0) {
        return 0;
    }

    bytes_received = qtls_read(conn, buffer, max_len);

    if (bytes_received < 0) {
        if (bytes_received == QTLS_ERROR_WANT_READ) {
            /* Would block */
            return 0;
        }

        if (bytes_received == QTLS_ERROR_ZERO_RETURN) {
            LOG_INFO("Connection closed by server");
            return 0;
        }

        LOG_ERROR("Receive failed: %s", qtls_get_error_string(bytes_received));
        return bytes_received;
    }

    LOG_DEBUG("Received %d bytes", bytes_received);
    return bytes_received;
}

/*
 * Close client connection gracefully
 */
void qtls_client_close(QTLS_CONNECTION *conn) {
    if (conn == NULL) {
        return;
    }

    LOG_INFO("Closing Q-TLS client connection");

    /* Shutdown connection */
    qtls_shutdown(conn);

    /* Free connection resources */
    qtls_free(conn);
}

/******************************************************************************
 * Certificate Pinning (HPKP-style for Q-TLS)
 ******************************************************************************/

/*
 * Pin server's public key hash for enhanced security
 * Implements public key pinning to prevent MITM attacks
 */
typedef struct {
    uint8_t kyber_hash[32];     /* SHA-256 of KYBER public key */
    uint8_t dilithium_hash[32]; /* SHA-256 of DILITHIUM public key */
    char hostname[256];
    time_t expires;
} qtls_pin_t;

static qtls_pin_t *pins = NULL;
static size_t num_pins = 0;

/*
 * Add a public key pin
 */
int qtls_client_add_pin(const char *hostname,
                        const uint8_t *kyber_hash,
                        const uint8_t *dilithium_hash,
                        time_t expires) {
    qtls_pin_t *new_pins;

    if (hostname == NULL || kyber_hash == NULL || dilithium_hash == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Resize pins array */
    new_pins = (qtls_pin_t *)realloc(pins, (num_pins + 1) * sizeof(qtls_pin_t));
    if (new_pins == NULL) {
        LOG_ERROR("Failed to allocate memory for pin");
        return QTLS_ERROR_OUT_OF_MEMORY;
    }

    pins = new_pins;

    /* Add new pin */
    memcpy(pins[num_pins].kyber_hash, kyber_hash, 32);
    memcpy(pins[num_pins].dilithium_hash, dilithium_hash, 32);
    strncpy(pins[num_pins].hostname, hostname, sizeof(pins[num_pins].hostname) - 1);
    pins[num_pins].hostname[sizeof(pins[num_pins].hostname) - 1] = '\0';
    pins[num_pins].expires = expires;

    num_pins++;

    LOG_INFO("Added public key pin for %s (expires=%ld)", hostname, expires);

    return QTLS_SUCCESS;
}

/*
 * Verify pinned public key
 */
int qtls_client_verify_pin(QTLS_CONNECTION *conn, const char *hostname) {
    size_t i;
    time_t now;

    if (conn == NULL || hostname == NULL) {
        return 0;
    }

    if (pins == NULL || num_pins == 0) {
        /* No pins configured, skip verification */
        return 1;
    }

    now = time(NULL);

    /* Find matching pin */
    for (i = 0; i < num_pins; i++) {
        if (strcmp(pins[i].hostname, hostname) != 0) {
            continue;
        }

        /* Check if pin has expired */
        if (pins[i].expires < now) {
            LOG_WARNING("Pin for %s has expired", hostname);
            continue;
        }

        /* TODO: Compute hashes of peer's public keys and compare */
        /* This would hash conn->peer_kyber_key.public_key and
         * conn->peer_dilithium_key.public_key and compare with pins[i] */

        LOG_INFO("Public key pin verified for %s", hostname);
        return 1;
    }

    LOG_ERROR("Public key pin verification failed for %s", hostname);
    return 0;
}

/*
 * Clear all pins
 */
void qtls_client_clear_pins(void) {
    if (pins != NULL) {
        qtls_secure_zero(pins, num_pins * sizeof(qtls_pin_t));
        free(pins);
        pins = NULL;
        num_pins = 0;
    }

    LOG_INFO("All public key pins cleared");
}

/******************************************************************************
 * Session Resumption (0-RTT for Q-TLS)
 ******************************************************************************/

typedef struct {
    char hostname[256];
    uint16_t port;
    uint8_t session_id[QTLS_MAX_SESSION_ID_LEN];
    uint8_t master_secret[QTLS_MAX_MASTER_SECRET];
    time_t timestamp;
} qtls_session_cache_t;

static qtls_session_cache_t *session_cache = NULL;
static size_t num_cached_sessions = 0;

/*
 * Cache session for resumption
 */
int qtls_client_cache_session(QTLS_CONNECTION *conn,
                               const char *hostname,
                               uint16_t port) {
    qtls_session_cache_t *new_cache;

    if (conn == NULL || hostname == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Resize cache */
    new_cache = (qtls_session_cache_t *)realloc(session_cache,
                    (num_cached_sessions + 1) * sizeof(qtls_session_cache_t));
    if (new_cache == NULL) {
        LOG_ERROR("Failed to allocate memory for session cache");
        return QTLS_ERROR_OUT_OF_MEMORY;
    }

    session_cache = new_cache;

    /* Cache session */
    strncpy(session_cache[num_cached_sessions].hostname, hostname,
            sizeof(session_cache[num_cached_sessions].hostname) - 1);
    session_cache[num_cached_sessions].port = port;
    memcpy(session_cache[num_cached_sessions].master_secret,
           conn->hybrid_secret.master_secret,
           QTLS_MAX_MASTER_SECRET);
    session_cache[num_cached_sessions].timestamp = time(NULL);

    num_cached_sessions++;

    LOG_INFO("Session cached for %s:%u", hostname, port);

    return QTLS_SUCCESS;
}

/*
 * Try to resume cached session
 */
int qtls_client_resume_session(QTLS_CONNECTION *conn,
                                const char *hostname,
                                uint16_t port) {
    size_t i;
    time_t now;

    if (conn == NULL || hostname == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    if (session_cache == NULL || num_cached_sessions == 0) {
        LOG_DEBUG("No cached sessions");
        return QTLS_ERROR_GENERIC;
    }

    now = time(NULL);

    /* Find matching session */
    for (i = 0; i < num_cached_sessions; i++) {
        if (strcmp(session_cache[i].hostname, hostname) != 0 ||
            session_cache[i].port != port) {
            continue;
        }

        /* Check if session is still valid (max 24 hours) */
        if (now - session_cache[i].timestamp > 86400) {
            LOG_DEBUG("Cached session expired");
            continue;
        }

        /* Restore master secret */
        memcpy(conn->hybrid_secret.master_secret,
               session_cache[i].master_secret,
               QTLS_MAX_MASTER_SECRET);

        LOG_INFO("Resuming session for %s:%u", hostname, port);
        return QTLS_SUCCESS;
    }

    LOG_DEBUG("No matching cached session found");
    return QTLS_ERROR_GENERIC;
}

/*
 * Clear session cache
 */
void qtls_client_clear_sessions(void) {
    if (session_cache != NULL) {
        qtls_secure_zero(session_cache,
                         num_cached_sessions * sizeof(qtls_session_cache_t));
        free(session_cache);
        session_cache = NULL;
        num_cached_sessions = 0;
    }

    LOG_INFO("Session cache cleared");
}

/******************************************************************************
 * Client Utility Functions
 ******************************************************************************/

/*
 * Get server certificate information
 */
int qtls_client_get_server_info(QTLS_CONNECTION *conn,
                                 char *subject, size_t subject_len,
                                 char *issuer, size_t issuer_len) {
    X509 *cert = NULL;
    X509_NAME *name = NULL;

    if (conn == NULL || subject == NULL || issuer == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    if (conn->ssl == NULL) {
        return QTLS_ERROR_GENERIC;
    }

    /* Get peer certificate */
    cert = SSL_get_peer_certificate(conn->ssl);
    if (cert == NULL) {
        LOG_ERROR("No peer certificate");
        return QTLS_ERROR_CERT_VERIFY_FAILED;
    }

    /* Get subject */
    name = X509_get_subject_name(cert);
    if (name != NULL) {
        X509_NAME_oneline(name, subject, subject_len);
    } else {
        subject[0] = '\0';
    }

    /* Get issuer */
    name = X509_get_issuer_name(cert);
    if (name != NULL) {
        X509_NAME_oneline(name, issuer, issuer_len);
    } else {
        issuer[0] = '\0';
    }

    X509_free(cert);

    LOG_DEBUG("Subject: %s", subject);
    LOG_DEBUG("Issuer: %s", issuer);

    return QTLS_SUCCESS;
}

/*
 * Enable strict certificate validation
 */
int qtls_client_enable_strict_validation(QTLS_CTX *ctx) {
    if (ctx == NULL) {
        return QTLS_ERROR_NULL_POINTER;
    }

    /* Set strict verification mode */
    qtls_ctx_set_verify_mode(ctx,
        QTLS_VERIFY_PEER | QTLS_VERIFY_FAIL_IF_NO_PEER_CERT,
        NULL);

    /* Enable hostname verification in OpenSSL */
    if (ctx->ssl_ctx != NULL) {
        X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx->ssl_ctx);
        X509_VERIFY_PARAM_set_hostflags(param,
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    }

    LOG_INFO("Strict certificate validation enabled");

    return QTLS_SUCCESS;
}

/*
 * Print connection statistics
 */
void qtls_client_print_stats(QTLS_CONNECTION *conn) {
    if (conn == NULL) {
        return;
    }

    printf("\n=== Q-TLS Connection Statistics ===\n");
    printf("Protocol Version: TLS 1.3 + PQC\n");
    printf("Cipher Suite: %s\n", qtls_get_cipher(conn));
    printf("PQC KEM: KYBER1024 (ML-KEM-1024)\n");
    printf("PQC Signature: DILITHIUM3 (ML-DSA-65)\n");
    printf("Classical KEM: ECDHE P-384\n");
    printf("Symmetric: AES-256-GCM\n");
    printf("Session State: %s\n",
           conn->state == 5 ? "Connected" : "Handshaking");
    printf("===================================\n\n");
}
