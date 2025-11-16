--[[
Q-TLS Plugin Schema for Apache APISIX
Copyright 2025 QSIGN Project

Configuration schema definition for Q-TLS plugin
--]]

return {
    type = "object",
    properties = {
        -- Server certificate path (hybrid RSA + DILITHIUM3)
        certificate = {
            type = "string",
            description = "Path to Q-TLS hybrid certificate file (PEM format)",
            default = "/etc/apisix/ssl/qtls-server-cert.pem"
        },

        -- HSM key URI for DILITHIUM3 private key
        hsm_key_uri = {
            type = "string",
            description = "PKCS#11 URI for server private key in Luna HSM",
            pattern = "^pkcs11:",
            examples = {
                "pkcs11:token=luna;object=qtls-server-key;type=private"
            }
        },

        -- PKCS#11 library path
        hsm_pkcs11_lib = {
            type = "string",
            description = "Path to Luna HSM PKCS#11 library",
            default = "/usr/lib/libCryptoki2_64.so"
        },

        -- Enable hybrid mode (KYBER1024 + DILITHIUM3)
        hybrid_mode = {
            type = "boolean",
            description = "Enable post-quantum hybrid cryptography",
            default = true
        },

        -- Mutual TLS configuration
        mutual_tls = {
            type = "boolean",
            description = "Enable mutual TLS (client certificate verification)",
            default = false
        },

        -- CA certificate for client verification
        client_ca_cert = {
            type = "string",
            description = "Path to QSIGN CA certificate bundle for client verification",
            default = "/etc/apisix/ssl/qsign-ca-bundle.pem"
        },

        -- Require Q-TLS for all requests
        require_qtls = {
            type = "boolean",
            description = "Reject non-Q-TLS connections",
            default = false
        },

        -- Allowed PQC algorithms
        allowed_kems = {
            type = "array",
            description = "Allowed Key Encapsulation Mechanisms",
            items = {
                type = "string",
                enum = {"KYBER512", "KYBER768", "KYBER1024"}
            },
            default = {"KYBER1024"}
        },

        allowed_signatures = {
            type = "array",
            description = "Allowed signature algorithms",
            items = {
                type = "string",
                enum = {"DILITHIUM2", "DILITHIUM3", "DILITHIUM5"}
            },
            default = {"DILITHIUM3"}
        },

        -- Session configuration
        session_timeout = {
            type = "integer",
            description = "Q-TLS session timeout in seconds",
            minimum = 60,
            maximum = 86400,
            default = 3600
        },

        session_cache_size = {
            type = "integer",
            description = "Maximum number of cached sessions",
            minimum = 10,
            maximum = 10000,
            default = 1000
        },

        -- Performance tuning
        max_handshakes_per_sec = {
            type = "integer",
            description = "Maximum Q-TLS handshakes per second (rate limiting)",
            minimum = 1,
            maximum = 10000,
            default = 1000
        },

        -- Logging configuration
        log_level = {
            type = "string",
            description = "Q-TLS plugin log level",
            enum = {"debug", "info", "warn", "error"},
            default = "info"
        },

        -- FIPS mode
        fips_mode = {
            type = "boolean",
            description = "Enable FIPS 140-2 compliant mode",
            default = false
        },

        -- Certificate chain validation
        verify_depth = {
            type = "integer",
            description = "Maximum certificate chain verification depth",
            minimum = 1,
            maximum = 10,
            default = 3
        },

        -- QSIGN integration
        qsign_root_ca = {
            type = "string",
            description = "Path to QSIGN root CA certificate",
            default = "/etc/apisix/ssl/qsign-root-ca.pem"
        },

        qsign_intermediate_ca = {
            type = "string",
            description = "Path to QSIGN intermediate CA certificate"
        },

        -- Upstream TLS configuration
        upstream_qtls = {
            type = "boolean",
            description = "Use Q-TLS for upstream connections",
            default = false
        },

        upstream_certificate = {
            type = "string",
            description = "Client certificate for upstream Q-TLS connections"
        },

        upstream_hsm_key_uri = {
            type = "string",
            description = "PKCS#11 URI for upstream client key"
        },

        -- Health check
        health_check = {
            type = "object",
            properties = {
                enabled = {
                    type = "boolean",
                    default = true
                },
                interval = {
                    type = "integer",
                    description = "Health check interval in seconds",
                    minimum = 10,
                    maximum = 3600,
                    default = 60
                },
                hsm_check = {
                    type = "boolean",
                    description = "Verify HSM connectivity",
                    default = true
                }
            }
        },

        -- Error handling
        fallback_to_classical = {
            type = "boolean",
            description = "Fallback to classical TLS if Q-TLS fails",
            default = false
        },

        -- Metrics
        enable_metrics = {
            type = "boolean",
            description = "Enable Prometheus metrics collection",
            default = true
        },

        metrics_endpoint = {
            type = "string",
            description = "Prometheus metrics endpoint path",
            default = "/qtls-metrics"
        }
    },

    -- Required fields
    required = {"certificate"},

    -- Conditional validation
    dependencies = {
        mutual_tls = {
            properties = {
                client_ca_cert = {
                    type = "string",
                    minLength = 1
                }
            },
            required = {"client_ca_cert"}
        },
        upstream_qtls = {
            properties = {
                upstream_certificate = {
                    type = "string",
                    minLength = 1
                }
            },
            required = {"upstream_certificate"}
        }
    },

    -- Additional validation rules
    additionalProperties = false
}
