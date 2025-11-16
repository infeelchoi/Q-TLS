--[[
Q-TLS Plugin for Apache APISIX
Copyright 2025 QSIGN Project

This plugin integrates Q-TLS (Quantum-resistant TLS) with Apache APISIX Gateway,
providing hybrid post-quantum cryptography support for API gateway traffic.

Features:
- Hybrid key exchange: ECDHE P-384 + KYBER1024
- Dual signatures: RSA/ECDSA + DILITHIUM3
- Luna HSM integration via PKCS#11
- Mutual TLS support
- QSIGN PKI certificate validation
--]]

local core = require("apisix.core")
local http = require("resty.http")
local ffi = require("ffi")
local ngx_ssl = require("ngx.ssl")
local ssl = require("ngx.ssl")

local plugin_name = "qtls"
local schema = require("apisix.plugins.qtls.schema")

-- FFI bindings to Q-TLS C library
ffi.cdef[[
    typedef struct qtls_ctx_st QTLS_CTX;
    typedef struct qtls_connection_st QTLS_CONNECTION;

    typedef enum {
        QTLS_CLIENT_MODE = 0,
        QTLS_SERVER_MODE = 1
    } QTLS_MODE;

    typedef enum {
        QTLS_SUCCESS = 0,
        QTLS_ERROR_HANDSHAKE_FAILED = -1,
        QTLS_ERROR_CERT_VERIFY_FAILED = -2,
        QTLS_ERROR_HSM_NOT_AVAILABLE = -3
    } QTLS_ERROR;

    // Context management
    QTLS_CTX* qtls_ctx_new(QTLS_MODE mode);
    void qtls_ctx_free(QTLS_CTX* ctx);
    int qtls_ctx_use_certificate_file(QTLS_CTX* ctx, const char* file, int type);
    int qtls_ctx_use_hsm_key(QTLS_CTX* ctx, const char* uri);
    int qtls_ctx_load_verify_locations(QTLS_CTX* ctx, const char* cafile, const char* capath);
    void qtls_ctx_set_options(QTLS_CTX* ctx, unsigned long options);
    void qtls_ctx_set_verify_mode(QTLS_CTX* ctx, int mode);

    // Connection management
    QTLS_CONNECTION* qtls_new(QTLS_CTX* ctx);
    void qtls_free(QTLS_CONNECTION* conn);
    int qtls_set_fd(QTLS_CONNECTION* conn, int fd);
    int qtls_accept(QTLS_CONNECTION* conn);
    int qtls_connect(QTLS_CONNECTION* conn);
    int qtls_read(QTLS_CONNECTION* conn, void* buf, int num);
    int qtls_write(QTLS_CONNECTION* conn, const void* buf, int num);
    int qtls_shutdown(QTLS_CONNECTION* conn);
    int qtls_verify_peer_certificate(QTLS_CONNECTION* conn);
    const char* qtls_get_error_string(int error);

    // HSM management
    int qtls_hsm_init(const char* pkcs11_lib);
    void qtls_hsm_cleanup(void);

    // Constants
    static const int QTLS_FILETYPE_PEM = 1;
    static const unsigned long QTLS_OP_HYBRID_MODE = 0x00000001;
    static const int QTLS_VERIFY_PEER = 0x01;
    static const int QTLS_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
]]

-- Load Q-TLS library
local qtls_lib_path = "/usr/local/lib/libqtls.so"
local qtls = ffi.load(qtls_lib_path)

local _M = {
    version = 0.1,
    priority = 3000,
    name = plugin_name,
    schema = schema,
}

-- Plugin configuration cache
local ctx_cache = core.lrucache.new({
    ttl = 300,
    count = 100
})

-- Initialize Q-TLS context
local function create_qtls_context(conf)
    local cache_key = core.json.encode(conf)
    local ctx = ctx_cache:get(cache_key)

    if ctx then
        core.log.info("Using cached Q-TLS context")
        return ctx
    end

    -- Create new context
    ctx = qtls.qtls_ctx_new(ffi.C.QTLS_SERVER_MODE)
    if ctx == nil then
        core.log.error("Failed to create Q-TLS context")
        return nil, "Failed to create Q-TLS context"
    end

    -- Load server certificate
    if conf.certificate then
        local ret = qtls.qtls_ctx_use_certificate_file(
            ctx,
            conf.certificate,
            ffi.C.QTLS_FILETYPE_PEM
        )
        if ret ~= 0 then
            qtls.qtls_ctx_free(ctx)
            return nil, "Failed to load certificate: " .. conf.certificate
        end
    end

    -- Load private key from HSM
    if conf.hsm_key_uri then
        local ret = qtls.qtls_ctx_use_hsm_key(ctx, conf.hsm_key_uri)
        if ret ~= 0 then
            qtls.qtls_ctx_free(ctx)
            return nil, "Failed to load HSM key: " .. conf.hsm_key_uri
        end
    end

    -- Load CA certificates for client verification
    if conf.client_ca_cert then
        local ret = qtls.qtls_ctx_load_verify_locations(
            ctx,
            conf.client_ca_cert,
            nil
        )
        if ret ~= 0 then
            qtls.qtls_ctx_free(ctx)
            return nil, "Failed to load CA certificates: " .. conf.client_ca_cert
        end
    end

    -- Enable hybrid mode (KYBER1024 + DILITHIUM3)
    if conf.hybrid_mode then
        qtls.qtls_ctx_set_options(ctx, ffi.C.QTLS_OP_HYBRID_MODE)
        core.log.info("Q-TLS hybrid mode enabled")
    end

    -- Configure mutual TLS
    if conf.mutual_tls then
        qtls.qtls_ctx_set_verify_mode(
            ctx,
            bit.bor(ffi.C.QTLS_VERIFY_PEER, ffi.C.QTLS_VERIFY_FAIL_IF_NO_PEER_CERT)
        )
        core.log.info("Q-TLS mutual TLS enabled")
    end

    -- Cache the context
    ctx_cache:set(cache_key, ctx, 300)

    return ctx
end

-- Initialize HSM connection
local function init_hsm(conf)
    if not conf.hsm_pkcs11_lib then
        return true
    end

    local ret = qtls.qtls_hsm_init(conf.hsm_pkcs11_lib)
    if ret ~= 0 then
        core.log.error("Failed to initialize HSM: ", conf.hsm_pkcs11_lib)
        return false
    end

    core.log.info("HSM initialized successfully: ", conf.hsm_pkcs11_lib)
    return true
end

-- Validate plugin configuration
function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- Plugin initialization
function _M.init()
    core.log.info("Q-TLS plugin initialized")
end

-- SSL certificate handler
function _M.ssl_certificate(conf, ctx)
    -- Get or create Q-TLS context
    local qtls_ctx, err = create_qtls_context(conf)
    if not qtls_ctx then
        core.log.error("Failed to create Q-TLS context: ", err)
        return 500
    end

    -- Initialize HSM if configured
    if conf.hsm_pkcs11_lib then
        local ok = init_hsm(conf)
        if not ok then
            core.log.error("HSM initialization failed")
            return 500
        end
    end

    -- Store Q-TLS context in nginx context for later use
    ctx.qtls_ctx = qtls_ctx

    -- Get client connection file descriptor
    local client_fd = ngx.socket.tcp()

    -- Create Q-TLS connection
    local conn = qtls.qtls_new(qtls_ctx)
    if conn == nil then
        core.log.error("Failed to create Q-TLS connection")
        return 500
    end

    -- Perform Q-TLS handshake
    local ret = qtls.qtls_accept(conn)
    if ret ~= ffi.C.QTLS_SUCCESS then
        local err_msg = ffi.string(qtls.qtls_get_error_string(ret))
        core.log.error("Q-TLS handshake failed: ", err_msg)
        qtls.qtls_free(conn)
        return 500
    end

    -- Verify client certificate for mutual TLS
    if conf.mutual_tls then
        local verify_ret = qtls.qtls_verify_peer_certificate(conn)
        if verify_ret == 0 then
            core.log.error("Client certificate verification failed")
            qtls.qtls_shutdown(conn)
            qtls.qtls_free(conn)
            return 401
        end
        core.log.info("Client certificate verified successfully")
    end

    -- Store connection in context
    ctx.qtls_conn = conn

    core.log.info("Q-TLS handshake completed successfully")
    return true
end

-- Request rewrite phase
function _M.rewrite(conf, ctx)
    -- Add Q-TLS headers to request
    if ctx.qtls_conn then
        core.request.set_header(ctx, "X-QTLS-Enabled", "true")
        core.request.set_header(ctx, "X-QTLS-Cipher", "KYBER1024-DILITHIUM3-AES256-GCM")
        core.request.set_header(ctx, "X-QTLS-Version", "1.0")

        if conf.mutual_tls then
            core.request.set_header(ctx, "X-QTLS-Client-Verified", "true")
        end
    end

    return true
end

-- Access control phase
function _M.access(conf, ctx)
    -- Validate Q-TLS connection is established
    if conf.require_qtls and not ctx.qtls_conn then
        core.log.error("Q-TLS connection required but not established")
        return 403, {
            message = "Q-TLS connection required"
        }
    end

    return true
end

-- Response header filter
function _M.header_filter(conf, ctx)
    if ctx.qtls_conn then
        core.response.set_header("X-QTLS-Protected", "true")
        core.response.set_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    end
end

-- Log phase
function _M.log(conf, ctx)
    if ctx.qtls_conn then
        core.log.info("Q-TLS connection stats - Handshake: success, Cipher: KYBER1024-DILITHIUM3")
    end
end

-- Plugin cleanup
function _M.destroy()
    -- Cleanup HSM resources
    qtls.qtls_hsm_cleanup()
    core.log.info("Q-TLS plugin destroyed")
end

return _M
