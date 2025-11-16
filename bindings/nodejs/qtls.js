/**
 * Q-TLS Node.js Binding
 * =====================
 *
 * Node.js binding for Q-TLS (Quantum-Resistant Transport Security Layer).
 * Provides a promise-based async API with EventEmitter support.
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 *
 * @example
 * // Server
 * const { QTLSServer, QTLS_SERVER_MODE, QTLS_OP_HYBRID_MODE } = require('qtls');
 *
 * const server = new QTLSServer({
 *   mode: QTLS_SERVER_MODE,
 *   cert: '/etc/qtls/server-cert.pem',
 *   key: '/etc/qtls/server-key.pem',
 *   hybrid: true
 * });
 *
 * server.listen(8443, () => {
 *   console.log('Q-TLS server listening on port 8443');
 * });
 *
 * server.on('connection', async (conn) => {
 *   const data = await conn.read();
 *   await conn.write('Hello from Q-TLS!');
 *   await conn.close();
 * });
 *
 * // Client
 * const { QTLSClient, QTLS_CLIENT_MODE } = require('qtls');
 *
 * const client = new QTLSClient({
 *   mode: QTLS_CLIENT_MODE,
 *   ca: '/etc/qtls/ca-bundle.pem',
 *   hybrid: true
 * });
 *
 * await client.connect('server.example.com', 8443);
 * await client.write('Hello Q-TLS!');
 * const response = await client.read();
 * await client.close();
 */

'use strict';

const EventEmitter = require('events');
const net = require('net');
const binding = require('./build/Release/qtls_native.node');

// Version information
const QTLS_VERSION = '1.0.0';

// Operating modes
const QTLS_CLIENT_MODE = 0;
const QTLS_SERVER_MODE = 1;

// Algorithm identifiers
const QTLSAlgorithm = {
  // Post-Quantum KEMs
  KEM_KYBER512: 0x0001,
  KEM_KYBER768: 0x0002,
  KEM_KYBER1024: 0x0003,

  // Post-Quantum Signatures
  SIG_DILITHIUM2: 0x0101,
  SIG_DILITHIUM3: 0x0102,
  SIG_DILITHIUM5: 0x0103,

  // Classical KEMs
  KEM_ECDHE_P256: 0x0201,
  KEM_ECDHE_P384: 0x0202,
  KEM_ECDHE_P521: 0x0203,

  // Classical Signatures
  SIG_RSA_2048: 0x0301,
  SIG_RSA_4096: 0x0302,
  SIG_ECDSA_P256: 0x0303,
  SIG_ECDSA_P384: 0x0304,

  // Symmetric ciphers
  CIPHER_AES_128_GCM: 0x0401,
  CIPHER_AES_256_GCM: 0x0402,
  CIPHER_CHACHA20_POLY1305: 0x0403
};

// Context options
const QTLS_OP_NO_SSLv2 = 0x00000001;
const QTLS_OP_NO_SSLv3 = 0x00000002;
const QTLS_OP_NO_TLSv1 = 0x00000004;
const QTLS_OP_NO_TLSv1_1 = 0x00000008;
const QTLS_OP_NO_TLSv1_2 = 0x00000010;
const QTLS_OP_HYBRID_MODE = 0x00000100;
const QTLS_OP_PQC_ONLY = 0x00000200;
const QTLS_OP_CLASSICAL_ONLY = 0x00000400;

// Verification modes
const QTLS_VERIFY_NONE = 0x00;
const QTLS_VERIFY_PEER = 0x01;
const QTLS_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
const QTLS_VERIFY_CLIENT_ONCE = 0x04;

// File types
const QTLS_FILETYPE_PEM = 1;
const QTLS_FILETYPE_ASN1 = 2;

// Error codes
const QTLSError = {
  SUCCESS: 0,
  ERROR_GENERIC: -1,
  ERROR_NULL_POINTER: -2,
  ERROR_INVALID_ARGUMENT: -3,
  ERROR_OUT_OF_MEMORY: -4,
  ERROR_SYSCALL: -5,
  ERROR_WANT_READ: -6,
  ERROR_WANT_WRITE: -7,
  ERROR_ZERO_RETURN: -8,

  // Crypto errors
  ERROR_CRYPTO_INIT: -100,
  ERROR_KEY_GENERATION: -101,
  ERROR_ENCAPSULATION: -102,
  ERROR_DECAPSULATION: -103,
  ERROR_SIGNATURE: -104,
  ERROR_VERIFICATION: -105,

  // Protocol errors
  ERROR_HANDSHAKE_FAILED: -200,
  ERROR_CERT_VERIFY_FAILED: -202,

  // HSM errors
  ERROR_HSM_NOT_AVAILABLE: -300
};

/**
 * Q-TLS Exception class
 */
class QTLSException extends Error {
  constructor(code, message) {
    super(message || binding.getErrorString(code));
    this.name = 'QTLSException';
    this.code = code;
  }
}

/**
 * Q-TLS Context for managing TLS configuration
 *
 * @example
 * const ctx = new QTLSContext({ mode: QTLS_SERVER_MODE });
 * ctx.useCertificateFile('/etc/qtls/server-cert.pem');
 * ctx.usePrivateKeyFile('/etc/qtls/server-key.pem');
 * ctx.setOptions(QTLS_OP_HYBRID_MODE);
 */
class QTLSContext {
  /**
   * Create a new Q-TLS context
   * @param {Object} options - Configuration options
   * @param {number} options.mode - QTLS_CLIENT_MODE or QTLS_SERVER_MODE
   * @param {string} [options.cert] - Path to certificate file
   * @param {string} [options.key] - Path to private key file
   * @param {string} [options.ca] - Path to CA bundle
   * @param {boolean} [options.hybrid=true] - Enable hybrid mode
   * @param {number} [options.verify] - Verification mode
   */
  constructor(options = {}) {
    const mode = options.mode || QTLS_CLIENT_MODE;
    this._ctx = binding.contextNew(mode);

    if (!this._ctx) {
      throw new QTLSException(QTLSError.ERROR_GENERIC, 'Failed to create Q-TLS context');
    }

    // Apply options
    if (options.cert) {
      this.useCertificateFile(options.cert);
    }

    if (options.key) {
      this.usePrivateKeyFile(options.key);
    }

    if (options.ca) {
      this.loadVerifyLocations(options.ca);
    }

    if (options.hybrid !== false) {
      this.setOptions(QTLS_OP_HYBRID_MODE);
    }

    if (options.verify !== undefined) {
      this.setVerifyMode(options.verify);
    }
  }

  /**
   * Set context options
   * @param {number} options - Bitmask of QTLS_OP_* flags
   */
  setOptions(options) {
    const ret = binding.contextSetOptions(this._ctx, options);
    if (ret !== 0) {
      throw new QTLSException(ret);
    }
  }

  /**
   * Set certificate verification mode
   * @param {number} mode - QTLS_VERIFY_* flags
   */
  setVerifyMode(mode) {
    const ret = binding.contextSetVerifyMode(this._ctx, mode);
    if (ret !== 0) {
      throw new QTLSException(ret);
    }
  }

  /**
   * Load certificate from file
   * @param {string} file - Path to certificate file
   * @param {number} [type=QTLS_FILETYPE_PEM] - File type
   */
  useCertificateFile(file, type = QTLS_FILETYPE_PEM) {
    const ret = binding.contextUseCertificateFile(this._ctx, file, type);
    if (ret !== 0) {
      throw new QTLSException(ret);
    }
  }

  /**
   * Load private key from file
   * @param {string} file - Path to private key file
   * @param {number} [type=QTLS_FILETYPE_PEM] - File type
   */
  usePrivateKeyFile(file, type = QTLS_FILETYPE_PEM) {
    const ret = binding.contextUsePrivateKeyFile(this._ctx, file, type);
    if (ret !== 0) {
      throw new QTLSException(ret);
    }
  }

  /**
   * Load private key from HSM
   * @param {string} uri - PKCS#11 URI
   */
  useHSMKey(uri) {
    const ret = binding.contextUseHSMKey(this._ctx, uri);
    if (ret !== 0) {
      throw new QTLSException(ret);
    }
  }

  /**
   * Load CA certificates for verification
   * @param {string} file - Path to CA bundle file
   * @param {string} [path] - Path to CA directory
   */
  loadVerifyLocations(file, path = null) {
    const ret = binding.contextLoadVerifyLocations(this._ctx, file, path);
    if (ret !== 0) {
      throw new QTLSException(ret);
    }
  }

  /**
   * Free the context
   */
  destroy() {
    if (this._ctx) {
      binding.contextFree(this._ctx);
      this._ctx = null;
    }
  }
}

/**
 * Q-TLS Connection wrapper
 *
 * @extends EventEmitter
 * @fires QTLSConnection#handshake
 * @fires QTLSConnection#data
 * @fires QTLSConnection#close
 * @fires QTLSConnection#error
 *
 * @example
 * const conn = new QTLSConnection(ctx, socket);
 * await conn.connect();
 *
 * conn.on('data', (data) => {
 *   console.log('Received:', data.toString());
 * });
 *
 * await conn.write('Hello!');
 * await conn.close();
 */
class QTLSConnection extends EventEmitter {
  /**
   * Create a new Q-TLS connection
   * @param {QTLSContext} ctx - Q-TLS context
   * @param {net.Socket} [socket] - Optional socket to wrap
   */
  constructor(ctx, socket = null) {
    super();

    this._conn = binding.connectionNew(ctx._ctx);
    if (!this._conn) {
      throw new QTLSException(QTLSError.ERROR_GENERIC, 'Failed to create Q-TLS connection');
    }

    this._ctx = ctx;
    this._socket = socket;

    if (socket) {
      this._setSocket(socket);
    }
  }

  /**
   * Set the socket for this connection
   * @private
   */
  _setSocket(socket) {
    this._socket = socket;
    const fd = socket._handle ? socket._handle.fd : -1;

    if (fd >= 0) {
      const ret = binding.connectionSetFd(this._conn, fd);
      if (ret !== 0) {
        throw new QTLSException(ret);
      }
    }
  }

  /**
   * Perform client-side handshake
   * @returns {Promise<void>}
   */
  async connect() {
    return new Promise((resolve, reject) => {
      const ret = binding.connectionConnect(this._conn);

      if (ret === 0) {
        this.emit('handshake');
        resolve();
      } else {
        const err = new QTLSException(ret);
        this.emit('error', err);
        reject(err);
      }
    });
  }

  /**
   * Perform server-side handshake
   * @returns {Promise<void>}
   */
  async accept() {
    return new Promise((resolve, reject) => {
      const ret = binding.connectionAccept(this._conn);

      if (ret === 0) {
        this.emit('handshake');
        resolve();
      } else {
        const err = new QTLSException(ret);
        this.emit('error', err);
        reject(err);
      }
    });
  }

  /**
   * Read encrypted data from connection
   * @param {number} [size=4096] - Maximum bytes to read
   * @returns {Promise<Buffer>}
   */
  async read(size = 4096) {
    return new Promise((resolve, reject) => {
      try {
        const result = binding.connectionRead(this._conn, size);

        if (result.error !== 0) {
          reject(new QTLSException(result.error));
        } else {
          const buffer = Buffer.from(result.data);
          this.emit('data', buffer);
          resolve(buffer);
        }
      } catch (err) {
        this.emit('error', err);
        reject(err);
      }
    });
  }

  /**
   * Write encrypted data to connection
   * @param {Buffer|string} data - Data to write
   * @returns {Promise<number>} Number of bytes written
   */
  async write(data) {
    return new Promise((resolve, reject) => {
      try {
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
        const result = binding.connectionWrite(this._conn, buffer);

        if (result < 0) {
          reject(new QTLSException(result));
        } else {
          resolve(result);
        }
      } catch (err) {
        this.emit('error', err);
        reject(err);
      }
    });
  }

  /**
   * Shutdown the connection
   * @returns {Promise<void>}
   */
  async shutdown() {
    return new Promise((resolve, reject) => {
      const ret = binding.connectionShutdown(this._conn);

      if (ret === 0 || ret === QTLSError.ERROR_ZERO_RETURN) {
        this.emit('close');
        resolve();
      } else {
        const err = new QTLSException(ret);
        this.emit('error', err);
        reject(err);
      }
    });
  }

  /**
   * Close the connection (alias for shutdown)
   * @returns {Promise<void>}
   */
  async close() {
    return this.shutdown();
  }

  /**
   * Verify peer certificate
   * @returns {boolean}
   */
  verifyPeerCertificate() {
    return binding.connectionVerifyPeerCertificate(this._conn) === 1;
  }

  /**
   * Free the connection
   */
  destroy() {
    if (this._conn) {
      binding.connectionFree(this._conn);
      this._conn = null;
    }
  }
}

/**
 * High-level Q-TLS Server
 *
 * @extends EventEmitter
 * @fires QTLSServer#listening
 * @fires QTLSServer#connection
 * @fires QTLSServer#error
 *
 * @example
 * const server = new QTLSServer({
 *   mode: QTLS_SERVER_MODE,
 *   cert: '/etc/qtls/server-cert.pem',
 *   key: '/etc/qtls/server-key.pem',
 *   hybrid: true
 * });
 *
 * server.on('connection', async (conn) => {
 *   const data = await conn.read();
 *   await conn.write('Echo: ' + data);
 *   await conn.close();
 * });
 *
 * server.listen(8443);
 */
class QTLSServer extends EventEmitter {
  /**
   * Create a new Q-TLS server
   * @param {Object} options - Server configuration
   */
  constructor(options = {}) {
    super();

    this._ctx = new QTLSContext({
      mode: QTLS_SERVER_MODE,
      ...options
    });

    this._server = null;
  }

  /**
   * Start listening for connections
   * @param {number} port - Port to listen on
   * @param {string} [host='0.0.0.0'] - Host to bind to
   * @param {Function} [callback] - Callback when listening
   */
  listen(port, host = '0.0.0.0', callback) {
    this._server = net.createServer((socket) => {
      this._handleConnection(socket);
    });

    this._server.listen(port, host, () => {
      this.emit('listening');
      if (callback) callback();
    });

    this._server.on('error', (err) => {
      this.emit('error', err);
    });
  }

  /**
   * Handle incoming connection
   * @private
   */
  async _handleConnection(socket) {
    try {
      const conn = new QTLSConnection(this._ctx, socket);
      await conn.accept();
      this.emit('connection', conn);
    } catch (err) {
      this.emit('error', err);
      socket.destroy();
    }
  }

  /**
   * Close the server
   * @param {Function} [callback] - Callback when closed
   */
  close(callback) {
    if (this._server) {
      this._server.close(callback);
    }
  }
}

/**
 * High-level Q-TLS Client
 *
 * @extends EventEmitter
 * @fires QTLSClient#connect
 * @fires QTLSClient#data
 * @fires QTLSClient#close
 * @fires QTLSClient#error
 *
 * @example
 * const client = new QTLSClient({
 *   mode: QTLS_CLIENT_MODE,
 *   ca: '/etc/qtls/ca-bundle.pem',
 *   hybrid: true
 * });
 *
 * await client.connect('server.example.com', 8443);
 * await client.write('Hello!');
 * const response = await client.read();
 * await client.close();
 */
class QTLSClient extends EventEmitter {
  /**
   * Create a new Q-TLS client
   * @param {Object} options - Client configuration
   */
  constructor(options = {}) {
    super();

    this._ctx = new QTLSContext({
      mode: QTLS_CLIENT_MODE,
      ...options
    });

    this._socket = null;
    this._conn = null;
  }

  /**
   * Connect to server
   * @param {string} host - Server hostname or IP
   * @param {number} [port=8443] - Server port
   * @returns {Promise<void>}
   */
  async connect(host, port = 8443) {
    return new Promise((resolve, reject) => {
      this._socket = new net.Socket();

      this._socket.connect(port, host, async () => {
        try {
          this._conn = new QTLSConnection(this._ctx, this._socket);
          await this._conn.connect();
          this.emit('connect');
          resolve();
        } catch (err) {
          this.emit('error', err);
          reject(err);
        }
      });

      this._socket.on('error', (err) => {
        this.emit('error', err);
        reject(err);
      });
    });
  }

  /**
   * Read data from server
   * @param {number} [size=4096] - Maximum bytes to read
   * @returns {Promise<Buffer>}
   */
  async read(size = 4096) {
    if (!this._conn) {
      throw new Error('Not connected');
    }
    return this._conn.read(size);
  }

  /**
   * Write data to server
   * @param {Buffer|string} data - Data to write
   * @returns {Promise<number>}
   */
  async write(data) {
    if (!this._conn) {
      throw new Error('Not connected');
    }
    return this._conn.write(data);
  }

  /**
   * Close the connection
   * @returns {Promise<void>}
   */
  async close() {
    if (this._conn) {
      await this._conn.shutdown();
      this.emit('close');
    }
    if (this._socket) {
      this._socket.destroy();
    }
  }

  /**
   * Verify server certificate
   * @returns {boolean}
   */
  verifyPeerCertificate() {
    if (!this._conn) {
      throw new Error('Not connected');
    }
    return this._conn.verifyPeerCertificate();
  }
}

/**
 * KYBER1024 post-quantum KEM wrapper
 *
 * @example
 * // Server
 * const kyber = new QTLSKyber();
 * await kyber.keygen();
 * const publicKey = kyber.getPublicKey();
 * // ... send to client ...
 * kyber.setCiphertext(ciphertext);
 * const secret = await kyber.decapsulate();
 *
 * // Client
 * const kyber = new QTLSKyber();
 * kyber.setPublicKey(serverPublicKey);
 * const secret = await kyber.encapsulate();
 * const ciphertext = kyber.getCiphertext();
 */
class QTLSKyber {
  constructor() {
    this._key = binding.kyberKeyNew();
  }

  /**
   * Generate KYBER1024 keypair
   * @returns {Promise<void>}
   */
  async keygen() {
    return new Promise((resolve, reject) => {
      const ret = binding.kyberKeygen(this._key);
      if (ret !== 0) {
        reject(new QTLSException(ret));
      } else {
        resolve();
      }
    });
  }

  /**
   * Encapsulate (client side)
   * @returns {Promise<Buffer>} Shared secret
   */
  async encapsulate() {
    return new Promise((resolve, reject) => {
      const result = binding.kyberEncapsulate(this._key);
      if (result.error !== 0) {
        reject(new QTLSException(result.error));
      } else {
        resolve(Buffer.from(result.sharedSecret));
      }
    });
  }

  /**
   * Decapsulate (server side)
   * @returns {Promise<Buffer>} Shared secret
   */
  async decapsulate() {
    return new Promise((resolve, reject) => {
      const result = binding.kyberDecapsulate(this._key);
      if (result.error !== 0) {
        reject(new QTLSException(result.error));
      } else {
        resolve(Buffer.from(result.sharedSecret));
      }
    });
  }

  /**
   * Get public key
   * @returns {Buffer}
   */
  getPublicKey() {
    return Buffer.from(binding.kyberGetPublicKey(this._key));
  }

  /**
   * Set public key
   * @param {Buffer} key - Public key
   */
  setPublicKey(key) {
    binding.kyberSetPublicKey(this._key, key);
  }

  /**
   * Get ciphertext
   * @returns {Buffer}
   */
  getCiphertext() {
    return Buffer.from(binding.kyberGetCiphertext(this._key));
  }

  /**
   * Set ciphertext
   * @param {Buffer} ct - Ciphertext
   */
  setCiphertext(ct) {
    binding.kyberSetCiphertext(this._key, ct);
  }

  destroy() {
    if (this._key) {
      binding.kyberKeyFree(this._key);
      this._key = null;
    }
  }
}

/**
 * DILITHIUM3 post-quantum signature wrapper
 *
 * @example
 * const dilithium = new QTLSDilithium();
 * await dilithium.keygen();
 * const signature = await dilithium.sign(Buffer.from('message'));
 * const isValid = await dilithium.verify(Buffer.from('message'), signature);
 */
class QTLSDilithium {
  constructor() {
    this._key = binding.dilithiumKeyNew();
  }

  /**
   * Generate DILITHIUM3 keypair
   * @returns {Promise<void>}
   */
  async keygen() {
    return new Promise((resolve, reject) => {
      const ret = binding.dilithiumKeygen(this._key);
      if (ret !== 0) {
        reject(new QTLSException(ret));
      } else {
        resolve();
      }
    });
  }

  /**
   * Sign message
   * @param {Buffer} message - Message to sign
   * @returns {Promise<Buffer>} Signature
   */
  async sign(message) {
    return new Promise((resolve, reject) => {
      const result = binding.dilithiumSign(this._key, message);
      if (result.error !== 0) {
        reject(new QTLSException(result.error));
      } else {
        resolve(Buffer.from(result.signature));
      }
    });
  }

  /**
   * Verify signature
   * @param {Buffer} message - Original message
   * @param {Buffer} signature - Signature to verify
   * @returns {Promise<boolean>}
   */
  async verify(message, signature) {
    return new Promise((resolve, reject) => {
      const ret = binding.dilithiumVerify(this._key, message, signature);
      if (ret === 1) {
        resolve(true);
      } else if (ret === 0) {
        resolve(false);
      } else {
        reject(new QTLSException(ret));
      }
    });
  }

  /**
   * Get public key
   * @returns {Buffer}
   */
  getPublicKey() {
    return Buffer.from(binding.dilithiumGetPublicKey(this._key));
  }

  /**
   * Set public key
   * @param {Buffer} key - Public key
   */
  setPublicKey(key) {
    binding.dilithiumSetPublicKey(this._key, key);
  }

  destroy() {
    if (this._key) {
      binding.dilithiumKeyFree(this._key);
      this._key = null;
    }
  }
}

/**
 * Get Q-TLS library version
 * @returns {string}
 */
function getVersion() {
  return binding.getVersion();
}

// Exports
module.exports = {
  // Version
  QTLS_VERSION,
  getVersion,

  // Modes
  QTLS_CLIENT_MODE,
  QTLS_SERVER_MODE,

  // Algorithms
  QTLSAlgorithm,

  // Options
  QTLS_OP_HYBRID_MODE,
  QTLS_OP_PQC_ONLY,
  QTLS_OP_CLASSICAL_ONLY,

  // Verification
  QTLS_VERIFY_NONE,
  QTLS_VERIFY_PEER,
  QTLS_VERIFY_FAIL_IF_NO_PEER_CERT,
  QTLS_VERIFY_CLIENT_ONCE,

  // File types
  QTLS_FILETYPE_PEM,
  QTLS_FILETYPE_ASN1,

  // Errors
  QTLSError,

  // Classes
  QTLSException,
  QTLSContext,
  QTLSConnection,
  QTLSServer,
  QTLSClient,
  QTLSKyber,
  QTLSDilithium
};
