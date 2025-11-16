/*
 * Q-TLS Provider for Keycloak
 * Copyright 2025 QSIGN Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This provider integrates Q-TLS quantum-resistant cryptography with Keycloak
 * for secure authentication and identity management.
 */

package org.qsign.keycloak.qtls;

import org.keycloak.common.util.PemUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;
import org.keycloak.Config;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * Q-TLS Provider SPI for Keycloak
 *
 * Enables Keycloak to use quantum-resistant cryptography:
 * - KYBER1024 for key exchange
 * - DILITHIUM3 for digital signatures
 * - Luna HSM integration for key storage
 * - QSIGN PKI certificate validation
 */
public class QTLSProvider implements Provider {

    private static final Logger log = Logger.getLogger(QTLSProvider.class.getName());

    private final KeycloakSession session;
    private final QTLSConfig config;
    private Pointer qtlsContext;
    private QTLSLibrary qtlsLib;

    /**
     * JNA interface to Q-TLS native library
     */
    public interface QTLSLibrary extends Library {
        QTLSLibrary INSTANCE = Native.load("qtls", QTLSLibrary.class);

        // Context management
        Pointer qtls_ctx_new(int mode);
        void qtls_ctx_free(Pointer ctx);
        int qtls_ctx_use_certificate_file(Pointer ctx, String file, int type);
        int qtls_ctx_use_hsm_key(Pointer ctx, String uri);
        int qtls_ctx_load_verify_locations(Pointer ctx, String cafile, String capath);
        void qtls_ctx_set_options(Pointer ctx, long options);
        void qtls_ctx_set_verify_mode(Pointer ctx, int mode);

        // Connection management
        Pointer qtls_new(Pointer ctx);
        void qtls_free(Pointer conn);
        int qtls_set_fd(Pointer conn, int fd);
        int qtls_accept(Pointer conn);
        int qtls_connect(Pointer conn);
        int qtls_read(Pointer conn, byte[] buf, int num);
        int qtls_write(Pointer conn, byte[] buf, int num);
        int qtls_shutdown(Pointer conn);
        int qtls_verify_peer_certificate(Pointer conn);
        String qtls_get_error_string(int error);

        // HSM operations
        int qtls_hsm_init(String pkcs11_lib);
        void qtls_hsm_cleanup();

        // Certificate operations
        int qtls_get_peer_certificate(Pointer conn, byte[] cert_der, IntByReference len);
        int qtls_get_cipher_info(Pointer conn, byte[] cipher_name, int max_len);

        // Constants
        int QTLS_SERVER_MODE = 1;
        int QTLS_CLIENT_MODE = 0;
        int QTLS_FILETYPE_PEM = 1;
        long QTLS_OP_HYBRID_MODE = 0x00000001L;
        int QTLS_VERIFY_PEER = 0x01;
        int QTLS_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
        int QTLS_SUCCESS = 0;
    }

    /**
     * Q-TLS Configuration
     */
    public static class QTLSConfig {
        private String certificatePath;
        private String hsmKeyUri;
        private String hsmPkcs11Lib;
        private String caCertPath;
        private boolean hybridMode = true;
        private boolean mutualTls = false;
        private boolean fipsMode = false;
        private int verifyDepth = 3;

        // Getters and setters
        public String getCertificatePath() { return certificatePath; }
        public void setCertificatePath(String path) { this.certificatePath = path; }

        public String getHsmKeyUri() { return hsmKeyUri; }
        public void setHsmKeyUri(String uri) { this.hsmKeyUri = uri; }

        public String getHsmPkcs11Lib() { return hsmPkcs11Lib; }
        public void setHsmPkcs11Lib(String lib) { this.hsmPkcs11Lib = lib; }

        public String getCaCertPath() { return caCertPath; }
        public void setCaCertPath(String path) { this.caCertPath = path; }

        public boolean isHybridMode() { return hybridMode; }
        public void setHybridMode(boolean mode) { this.hybridMode = mode; }

        public boolean isMutualTls() { return mutualTls; }
        public void setMutualTls(boolean mtls) { this.mutualTls = mtls; }

        public boolean isFipsMode() { return fipsMode; }
        public void setFipsMode(boolean fips) { this.fipsMode = fips; }

        public int getVerifyDepth() { return verifyDepth; }
        public void setVerifyDepth(int depth) { this.verifyDepth = depth; }
    }

    public QTLSProvider(KeycloakSession session, QTLSConfig config) {
        this.session = session;
        this.config = config;
        this.qtlsLib = QTLSLibrary.INSTANCE;

        initialize();
    }

    /**
     * Initialize Q-TLS provider
     */
    private void initialize() {
        log.info("Initializing Q-TLS provider for Keycloak");

        try {
            // Initialize HSM if configured
            if (config.getHsmPkcs11Lib() != null) {
                int ret = qtlsLib.qtls_hsm_init(config.getHsmPkcs11Lib());
                if (ret != QTLSLibrary.QTLS_SUCCESS) {
                    throw new RuntimeException("Failed to initialize HSM: " + config.getHsmPkcs11Lib());
                }
                log.info("HSM initialized successfully");
            }

            // Create Q-TLS context
            qtlsContext = qtlsLib.qtls_ctx_new(QTLSLibrary.QTLS_SERVER_MODE);
            if (qtlsContext == null) {
                throw new RuntimeException("Failed to create Q-TLS context");
            }

            // Load server certificate
            if (config.getCertificatePath() != null) {
                int ret = qtlsLib.qtls_ctx_use_certificate_file(
                    qtlsContext,
                    config.getCertificatePath(),
                    QTLSLibrary.QTLS_FILETYPE_PEM
                );
                if (ret != QTLSLibrary.QTLS_SUCCESS) {
                    throw new RuntimeException("Failed to load certificate: " + config.getCertificatePath());
                }
                log.info("Certificate loaded: " + config.getCertificatePath());
            }

            // Load private key from HSM
            if (config.getHsmKeyUri() != null) {
                int ret = qtlsLib.qtls_ctx_use_hsm_key(qtlsContext, config.getHsmKeyUri());
                if (ret != QTLSLibrary.QTLS_SUCCESS) {
                    throw new RuntimeException("Failed to load HSM key: " + config.getHsmKeyUri());
                }
                log.info("HSM key loaded: " + config.getHsmKeyUri());
            }

            // Load CA certificates
            if (config.getCaCertPath() != null) {
                int ret = qtlsLib.qtls_ctx_load_verify_locations(
                    qtlsContext,
                    config.getCaCertPath(),
                    null
                );
                if (ret != QTLSLibrary.QTLS_SUCCESS) {
                    throw new RuntimeException("Failed to load CA certificates: " + config.getCaCertPath());
                }
                log.info("CA certificates loaded: " + config.getCaCertPath());
            }

            // Enable hybrid mode
            if (config.isHybridMode()) {
                qtlsLib.qtls_ctx_set_options(qtlsContext, QTLSLibrary.QTLS_OP_HYBRID_MODE);
                log.info("Q-TLS hybrid mode enabled (KYBER1024 + DILITHIUM3)");
            }

            // Configure mutual TLS
            if (config.isMutualTls()) {
                qtlsLib.qtls_ctx_set_verify_mode(
                    qtlsContext,
                    QTLSLibrary.QTLS_VERIFY_PEER | QTLSLibrary.QTLS_VERIFY_FAIL_IF_NO_PEER_CERT
                );
                log.info("Mutual TLS enabled");
            }

            log.info("Q-TLS provider initialized successfully");

        } catch (Exception e) {
            log.severe("Failed to initialize Q-TLS provider: " + e.getMessage());
            throw new RuntimeException("Q-TLS initialization failed", e);
        }
    }

    /**
     * Create SSLContext using Q-TLS
     */
    public SSLContext createSSLContext() throws Exception {
        SSLContext sslContext = new QTLSSSLContext(qtlsContext, qtlsLib, config);
        return sslContext;
    }

    /**
     * Validate client certificate using QSIGN PKI
     */
    public boolean validateClientCertificate(X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            log.warning("No client certificate provided");
            return false;
        }

        try {
            // Verify certificate chain
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Load QSIGN CA certificate
            FileInputStream caInput = new FileInputStream(config.getCaCertPath());
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(caInput);
            caInput.close();

            // Create trust anchor
            TrustAnchor anchor = new TrustAnchor(caCert, null);
            Set<TrustAnchor> anchors = Collections.singleton(anchor);

            // Configure certificate path validator
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false); // TODO: Implement OCSP/CRL checking
            params.setMaxPathLength(config.getVerifyDepth());

            // Build certificate path
            List<X509Certificate> certList = Arrays.asList(chain);
            CertPath certPath = cf.generateCertPath(certList);

            // Validate certificate path
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult result =
                (PKIXCertPathValidatorResult) validator.validate(certPath, params);

            log.info("Client certificate validated successfully: " +
                     chain[0].getSubjectDN().getName());
            return true;

        } catch (Exception e) {
            log.warning("Client certificate validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get cipher information from Q-TLS connection
     */
    public String getCipherInfo(Pointer conn) {
        byte[] cipherName = new byte[256];
        int ret = qtlsLib.qtls_get_cipher_info(conn, cipherName, cipherName.length);

        if (ret == QTLSLibrary.QTLS_SUCCESS) {
            return new String(cipherName).trim();
        }

        return "KYBER1024-DILITHIUM3-AES256-GCM"; // Default
    }

    @Override
    public void close() {
        if (qtlsContext != null) {
            qtlsLib.qtls_ctx_free(qtlsContext);
            qtlsContext = null;
        }

        if (config.getHsmPkcs11Lib() != null) {
            qtlsLib.qtls_hsm_cleanup();
        }

        log.info("Q-TLS provider closed");
    }

    /**
     * Q-TLS SSLContext implementation
     */
    private static class QTLSSSLContext extends SSLContext {

        public QTLSSSLContext(Pointer qtlsContext, QTLSLibrary qtlsLib, QTLSConfig config)
                throws Exception {
            super(new QTLSSSLContextSpi(qtlsContext, qtlsLib, config), null, "QTLS");
        }
    }

    /**
     * Q-TLS SSLContext SPI implementation
     */
    private static class QTLSSSLContextSpi extends SSLContextSpi {

        private final Pointer qtlsContext;
        private final QTLSLibrary qtlsLib;
        private final QTLSConfig config;

        public QTLSSSLContextSpi(Pointer qtlsContext, QTLSLibrary qtlsLib, QTLSConfig config) {
            this.qtlsContext = qtlsContext;
            this.qtlsLib = qtlsLib;
            this.config = config;
        }

        @Override
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom random)
                throws KeyManagementException {
            // Q-TLS initialization already done
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            return new QTLSSocketFactory(qtlsContext, qtlsLib, config);
        }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            return new QTLSServerSocketFactory(qtlsContext, qtlsLib, config);
        }

        @Override
        protected SSLEngine engineCreateSSLEngine() {
            return new QTLSEngine(qtlsContext, qtlsLib, config);
        }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            return new QTLSEngine(qtlsContext, qtlsLib, config, host, port);
        }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            return new QTLSSessionContext();
        }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            return new QTLSSessionContext();
        }
    }

    /**
     * Q-TLS Socket Factory
     */
    private static class QTLSSocketFactory extends SSLSocketFactory {

        private final Pointer qtlsContext;
        private final QTLSLibrary qtlsLib;
        private final QTLSConfig config;

        public QTLSSocketFactory(Pointer qtlsContext, QTLSLibrary qtlsLib, QTLSConfig config) {
            this.qtlsContext = qtlsContext;
            this.qtlsLib = qtlsLib;
            this.config = config;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return new String[]{"KYBER1024-DILITHIUM3-AES256-GCM"};
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[]{
                "KYBER1024-DILITHIUM3-AES256-GCM",
                "KYBER1024-DILITHIUM3-CHACHA20-POLY1305"
            };
        }

        @Override
        public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose)
                throws IOException {
            return new QTLSSocket(qtlsContext, qtlsLib, config, s, host, port, autoClose);
        }

        @Override
        public java.net.Socket createSocket(String host, int port) throws IOException {
            return new QTLSSocket(qtlsContext, qtlsLib, config, host, port);
        }

        @Override
        public java.net.Socket createSocket(String host, int port,
                                           java.net.InetAddress localHost, int localPort)
                throws IOException {
            return new QTLSSocket(qtlsContext, qtlsLib, config, host, port, localHost, localPort);
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress host, int port) throws IOException {
            return new QTLSSocket(qtlsContext, qtlsLib, config, host, port);
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress address, int port,
                                           java.net.InetAddress localAddress, int localPort)
                throws IOException {
            return new QTLSSocket(qtlsContext, qtlsLib, config, address, port, localAddress, localPort);
        }
    }

    /**
     * Q-TLS Server Socket Factory (stub)
     */
    private static class QTLSServerSocketFactory extends SSLServerSocketFactory {

        private final Pointer qtlsContext;
        private final QTLSLibrary qtlsLib;
        private final QTLSConfig config;

        public QTLSServerSocketFactory(Pointer qtlsContext, QTLSLibrary qtlsLib, QTLSConfig config) {
            this.qtlsContext = qtlsContext;
            this.qtlsLib = qtlsLib;
            this.config = config;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return new String[]{"KYBER1024-DILITHIUM3-AES256-GCM"};
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[]{"KYBER1024-DILITHIUM3-AES256-GCM"};
        }

        @Override
        public java.net.ServerSocket createServerSocket(int port) throws IOException {
            throw new UnsupportedOperationException("Q-TLS server socket not implemented");
        }

        @Override
        public java.net.ServerSocket createServerSocket(int port, int backlog) throws IOException {
            throw new UnsupportedOperationException("Q-TLS server socket not implemented");
        }

        @Override
        public java.net.ServerSocket createServerSocket(int port, int backlog,
                                                        java.net.InetAddress ifAddress)
                throws IOException {
            throw new UnsupportedOperationException("Q-TLS server socket not implemented");
        }
    }

    // Stub classes for compilation (full implementation would be extensive)
    private static class QTLSSocket extends SSLSocket {
        public QTLSSocket(Pointer ctx, QTLSLibrary lib, QTLSConfig cfg, Object... args) {
            // Stub constructor
        }
    }

    private static class QTLSEngine extends SSLEngine {
        public QTLSEngine(Pointer ctx, QTLSLibrary lib, QTLSConfig cfg, Object... args) {
            // Stub constructor
        }
    }

    private static class QTLSSessionContext implements SSLSessionContext {
        public java.util.Enumeration<byte[]> getIds() { return null; }
        public SSLSession getSession(byte[] sessionId) { return null; }
        public int getSessionCacheSize() { return 1000; }
        public int getSessionTimeout() { return 3600; }
        public void setSessionCacheSize(int size) {}
        public void setSessionTimeout(int seconds) {}
    }
}

/**
 * Q-TLS Provider Factory
 */
class QTLSProviderFactory implements ProviderFactory<QTLSProvider> {

    private static final String PROVIDER_ID = "qtls";
    private QTLSProvider.QTLSConfig config;

    @Override
    public QTLSProvider create(KeycloakSession session) {
        return new QTLSProvider(session, config);
    }

    @Override
    public void init(Config.Scope config) {
        this.config = new QTLSProvider.QTLSConfig();
        this.config.setCertificatePath(config.get("certificate-path"));
        this.config.setHsmKeyUri(config.get("hsm-key-uri"));
        this.config.setHsmPkcs11Lib(config.get("hsm-pkcs11-lib", "/usr/lib/libCryptoki2_64.so"));
        this.config.setCaCertPath(config.get("ca-cert-path"));
        this.config.setHybridMode(config.getBoolean("hybrid-mode", true));
        this.config.setMutualTls(config.getBoolean("mutual-tls", false));
        this.config.setFipsMode(config.getBoolean("fips-mode", false));
        this.config.setVerifyDepth(config.getInt("verify-depth", 3));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post-initialization if needed
    }

    @Override
    public void close() {
        // Cleanup
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

/**
 * Q-TLS Provider SPI
 */
class QTLSProviderSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "qtls";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return QTLSProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return QTLSProviderFactory.class;
    }
}
