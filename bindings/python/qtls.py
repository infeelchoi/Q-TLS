"""
Q-TLS Python Binding
====================

Python binding for Q-TLS (Quantum-Resistant Transport Security Layer).
Provides a high-level interface to the Q-TLS C library with support for
hybrid post-quantum cryptography.

Copyright 2025 QSIGN Project
Licensed under the Apache License, Version 2.0

Example usage:
    # Server
    ctx = QTLSContext(mode=QTLS_SERVER_MODE)
    ctx.use_certificate_file('/etc/qtls/server-cert.pem')
    ctx.use_private_key_file('/etc/qtls/server-key.pem')
    ctx.set_options(QTLS_OP_HYBRID_MODE)

    server = QTLSServer(ctx, '0.0.0.0', 8443)
    for conn in server.accept_connections():
        data = conn.read(4096)
        conn.write(b'Hello from Q-TLS!')
        conn.shutdown()

    # Client
    ctx = QTLSContext(mode=QTLS_CLIENT_MODE)
    ctx.load_verify_locations('/etc/qtls/ca-bundle.pem')
    ctx.set_options(QTLS_OP_HYBRID_MODE)

    client = QTLSClient(ctx)
    client.connect('server.example.com', 8443)
    client.write(b'Hello Q-TLS!')
    response = client.read(4096)
    client.shutdown()
"""

import ctypes
import socket
import os
import threading
from typing import Optional, Tuple, List, Callable
from enum import IntEnum


# Version information
QTLS_VERSION_MAJOR = 1
QTLS_VERSION_MINOR = 0
QTLS_VERSION_PATCH = 0
QTLS_VERSION_STRING = "1.0.0"


# Operating modes
QTLS_CLIENT_MODE = 0
QTLS_SERVER_MODE = 1


# Algorithm identifiers
class QTLSAlgorithm(IntEnum):
    """Q-TLS algorithm identifiers"""
    # Post-Quantum KEMs
    KEM_KYBER512 = 0x0001
    KEM_KYBER768 = 0x0002
    KEM_KYBER1024 = 0x0003

    # Post-Quantum Signatures
    SIG_DILITHIUM2 = 0x0101
    SIG_DILITHIUM3 = 0x0102
    SIG_DILITHIUM5 = 0x0103

    # Classical KEMs
    KEM_ECDHE_P256 = 0x0201
    KEM_ECDHE_P384 = 0x0202
    KEM_ECDHE_P521 = 0x0203

    # Classical Signatures
    SIG_RSA_2048 = 0x0301
    SIG_RSA_4096 = 0x0302
    SIG_ECDSA_P256 = 0x0303
    SIG_ECDSA_P384 = 0x0304

    # Symmetric ciphers
    CIPHER_AES_128_GCM = 0x0401
    CIPHER_AES_256_GCM = 0x0402
    CIPHER_CHACHA20_POLY1305 = 0x0403


# Context options
QTLS_OP_NO_SSLv2 = 0x00000001
QTLS_OP_NO_SSLv3 = 0x00000002
QTLS_OP_NO_TLSv1 = 0x00000004
QTLS_OP_NO_TLSv1_1 = 0x00000008
QTLS_OP_NO_TLSv1_2 = 0x00000010
QTLS_OP_HYBRID_MODE = 0x00000100
QTLS_OP_PQC_ONLY = 0x00000200
QTLS_OP_CLASSICAL_ONLY = 0x00000400


# Verification modes
QTLS_VERIFY_NONE = 0x00
QTLS_VERIFY_PEER = 0x01
QTLS_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02
QTLS_VERIFY_CLIENT_ONCE = 0x04


# File types
QTLS_FILETYPE_PEM = 1
QTLS_FILETYPE_ASN1 = 2


# Error codes
class QTLSError(IntEnum):
    """Q-TLS error codes"""
    SUCCESS = 0
    ERROR_NONE = 0
    ERROR_GENERIC = -1
    ERROR_NULL_POINTER = -2
    ERROR_INVALID_ARGUMENT = -3
    ERROR_OUT_OF_MEMORY = -4
    ERROR_SYSCALL = -5
    ERROR_WANT_READ = -6
    ERROR_WANT_WRITE = -7
    ERROR_ZERO_RETURN = -8

    # Crypto errors
    ERROR_CRYPTO_INIT = -100
    ERROR_KEY_GENERATION = -101
    ERROR_ENCAPSULATION = -102
    ERROR_DECAPSULATION = -103
    ERROR_SIGNATURE = -104
    ERROR_VERIFICATION = -105
    ERROR_KEY_DERIVATION = -106
    ERROR_ENCRYPTION = -107
    ERROR_DECRYPTION = -108

    # Protocol errors
    ERROR_HANDSHAKE_FAILED = -200
    ERROR_PROTOCOL_VERSION = -201
    ERROR_CERT_VERIFY_FAILED = -202
    ERROR_PEER_CLOSED = -203
    ERROR_INVALID_MESSAGE = -204
    ERROR_UNSUPPORTED_ALGO = -205

    # HSM errors
    ERROR_HSM_NOT_AVAILABLE = -300
    ERROR_HSM_INIT_FAILED = -301
    ERROR_HSM_LOGIN_FAILED = -302
    ERROR_HSM_KEY_NOT_FOUND = -303
    ERROR_HSM_OPERATION_FAILED = -304


# Constants
QTLS_KYBER1024_PUBLIC_KEY_BYTES = 1568
QTLS_KYBER1024_SECRET_KEY_BYTES = 3168
QTLS_KYBER1024_CIPHERTEXT_BYTES = 1568
QTLS_KYBER1024_SHARED_SECRET_BYTES = 32

QTLS_DILITHIUM3_PUBLIC_KEY_BYTES = 1952
QTLS_DILITHIUM3_SECRET_KEY_BYTES = 4000
QTLS_DILITHIUM3_SIGNATURE_BYTES = 3293


class QTLSException(Exception):
    """Exception raised for Q-TLS errors"""
    def __init__(self, error_code: int, message: str = None):
        self.error_code = error_code
        if message is None:
            try:
                message = _lib.qtls_get_error_string(error_code).decode('utf-8')
            except:
                message = f"Q-TLS error {error_code}"
        super().__init__(message)


# Load Q-TLS library
def _load_library():
    """Load the Q-TLS shared library"""
    lib_names = ['libqtls.so.1', 'libqtls.so', 'qtls.so', 'libqtls.dylib', 'qtls.dll']
    lib_paths = [
        '/usr/local/lib',
        '/usr/lib',
        '/usr/lib/x86_64-linux-gnu',
        os.path.join(os.path.dirname(__file__), '..', '..', 'build'),
    ]

    for lib_path in lib_paths + ['']:
        for lib_name in lib_names:
            try:
                if lib_path:
                    full_path = os.path.join(lib_path, lib_name)
                else:
                    full_path = lib_name
                lib = ctypes.CDLL(full_path)
                return lib
            except OSError:
                continue

    raise ImportError("Could not load Q-TLS library. Please ensure it is installed.")


_lib = _load_library()


# Define C structures and function prototypes
class QTLS_KYBER_KEY(ctypes.Structure):
    """KYBER1024 key structure"""
    _fields_ = [
        ('public_key', ctypes.c_uint8 * QTLS_KYBER1024_PUBLIC_KEY_BYTES),
        ('secret_key', ctypes.c_uint8 * QTLS_KYBER1024_SECRET_KEY_BYTES),
        ('ciphertext', ctypes.c_uint8 * QTLS_KYBER1024_CIPHERTEXT_BYTES),
        ('shared_secret', ctypes.c_uint8 * QTLS_KYBER1024_SHARED_SECRET_BYTES),
        ('has_secret_key', ctypes.c_int),
        ('has_shared_secret', ctypes.c_int),
    ]


class QTLS_DILITHIUM_KEY(ctypes.Structure):
    """DILITHIUM3 key structure"""
    _fields_ = [
        ('public_key', ctypes.c_uint8 * QTLS_DILITHIUM3_PUBLIC_KEY_BYTES),
        ('secret_key', ctypes.c_uint8 * QTLS_DILITHIUM3_SECRET_KEY_BYTES),
        ('has_secret_key', ctypes.c_int),
    ]


# Function prototypes
_lib.qtls_ctx_new.argtypes = [ctypes.c_int]
_lib.qtls_ctx_new.restype = ctypes.c_void_p

_lib.qtls_ctx_free.argtypes = [ctypes.c_void_p]
_lib.qtls_ctx_free.restype = None

_lib.qtls_ctx_set_options.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
_lib.qtls_ctx_set_options.restype = ctypes.c_int

_lib.qtls_ctx_set_verify_mode.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
_lib.qtls_ctx_set_verify_mode.restype = ctypes.c_int

_lib.qtls_ctx_use_certificate_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
_lib.qtls_ctx_use_certificate_file.restype = ctypes.c_int

_lib.qtls_ctx_use_private_key_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
_lib.qtls_ctx_use_private_key_file.restype = ctypes.c_int

_lib.qtls_ctx_use_hsm_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_lib.qtls_ctx_use_hsm_key.restype = ctypes.c_int

_lib.qtls_ctx_load_verify_locations.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.qtls_ctx_load_verify_locations.restype = ctypes.c_int

_lib.qtls_new.argtypes = [ctypes.c_void_p]
_lib.qtls_new.restype = ctypes.c_void_p

_lib.qtls_free.argtypes = [ctypes.c_void_p]
_lib.qtls_free.restype = None

_lib.qtls_set_fd.argtypes = [ctypes.c_void_p, ctypes.c_int]
_lib.qtls_set_fd.restype = ctypes.c_int

_lib.qtls_connect.argtypes = [ctypes.c_void_p]
_lib.qtls_connect.restype = ctypes.c_int

_lib.qtls_accept.argtypes = [ctypes.c_void_p]
_lib.qtls_accept.restype = ctypes.c_int

_lib.qtls_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
_lib.qtls_read.restype = ctypes.c_int

_lib.qtls_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
_lib.qtls_write.restype = ctypes.c_int

_lib.qtls_shutdown.argtypes = [ctypes.c_void_p]
_lib.qtls_shutdown.restype = ctypes.c_int

_lib.qtls_verify_peer_certificate.argtypes = [ctypes.c_void_p]
_lib.qtls_verify_peer_certificate.restype = ctypes.c_int

_lib.qtls_get_error_string.argtypes = [ctypes.c_int]
_lib.qtls_get_error_string.restype = ctypes.c_char_p

_lib.qtls_version.argtypes = []
_lib.qtls_version.restype = ctypes.c_char_p

_lib.qtls_kyber_keygen.argtypes = [ctypes.POINTER(QTLS_KYBER_KEY)]
_lib.qtls_kyber_keygen.restype = ctypes.c_int

_lib.qtls_kyber_encapsulate.argtypes = [ctypes.POINTER(QTLS_KYBER_KEY)]
_lib.qtls_kyber_encapsulate.restype = ctypes.c_int

_lib.qtls_kyber_decapsulate.argtypes = [ctypes.POINTER(QTLS_KYBER_KEY)]
_lib.qtls_kyber_decapsulate.restype = ctypes.c_int

_lib.qtls_dilithium_keygen.argtypes = [ctypes.POINTER(QTLS_DILITHIUM_KEY)]
_lib.qtls_dilithium_keygen.restype = ctypes.c_int

_lib.qtls_dilithium_sign.argtypes = [
    ctypes.POINTER(QTLS_DILITHIUM_KEY),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t)
]
_lib.qtls_dilithium_sign.restype = ctypes.c_int

_lib.qtls_dilithium_verify.argtypes = [
    ctypes.POINTER(QTLS_DILITHIUM_KEY),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t
]
_lib.qtls_dilithium_verify.restype = ctypes.c_int


class QTLSContext:
    """
    Q-TLS context for managing TLS configuration.

    Example:
        ctx = QTLSContext(mode=QTLS_SERVER_MODE)
        ctx.use_certificate_file('/etc/qtls/server-cert.pem')
        ctx.use_private_key_file('/etc/qtls/server-key.pem')
        ctx.set_options(QTLS_OP_HYBRID_MODE)
    """

    def __init__(self, mode: int = QTLS_CLIENT_MODE):
        """
        Create a new Q-TLS context.

        Args:
            mode: QTLS_CLIENT_MODE or QTLS_SERVER_MODE
        """
        self._ctx = _lib.qtls_ctx_new(mode)
        if not self._ctx:
            raise QTLSException(QTLSError.ERROR_GENERIC, "Failed to create Q-TLS context")
        self._mode = mode

    def __del__(self):
        """Free the context"""
        if hasattr(self, '_ctx') and self._ctx:
            _lib.qtls_ctx_free(self._ctx)

    def set_options(self, options: int) -> None:
        """
        Set context options.

        Args:
            options: Bitmask of QTLS_OP_* flags
        """
        ret = _lib.qtls_ctx_set_options(self._ctx, options)
        if ret != 0:
            raise QTLSException(ret)

    def set_verify_mode(self, mode: int) -> None:
        """
        Set certificate verification mode.

        Args:
            mode: QTLS_VERIFY_* flags
        """
        ret = _lib.qtls_ctx_set_verify_mode(self._ctx, mode, None)
        if ret != 0:
            raise QTLSException(ret)

    def use_certificate_file(self, file_path: str, file_type: int = QTLS_FILETYPE_PEM) -> None:
        """
        Load certificate from file.

        Args:
            file_path: Path to certificate file
            file_type: QTLS_FILETYPE_PEM or QTLS_FILETYPE_ASN1
        """
        ret = _lib.qtls_ctx_use_certificate_file(self._ctx, file_path.encode('utf-8'), file_type)
        if ret != 0:
            raise QTLSException(ret)

    def use_private_key_file(self, file_path: str, file_type: int = QTLS_FILETYPE_PEM) -> None:
        """
        Load private key from file.

        Args:
            file_path: Path to private key file
            file_type: QTLS_FILETYPE_PEM or QTLS_FILETYPE_ASN1
        """
        ret = _lib.qtls_ctx_use_private_key_file(self._ctx, file_path.encode('utf-8'), file_type)
        if ret != 0:
            raise QTLSException(ret)

    def use_hsm_key(self, uri: str) -> None:
        """
        Load private key from HSM using PKCS#11 URI.

        Args:
            uri: PKCS#11 URI (e.g., "pkcs11:token=luna;object=mykey")
        """
        ret = _lib.qtls_ctx_use_hsm_key(self._ctx, uri.encode('utf-8'))
        if ret != 0:
            raise QTLSException(ret)

    def load_verify_locations(self, ca_file: Optional[str] = None, ca_path: Optional[str] = None) -> None:
        """
        Load CA certificates for verification.

        Args:
            ca_file: Path to CA bundle file
            ca_path: Path to CA directory
        """
        ca_file_c = ca_file.encode('utf-8') if ca_file else None
        ca_path_c = ca_path.encode('utf-8') if ca_path else None
        ret = _lib.qtls_ctx_load_verify_locations(self._ctx, ca_file_c, ca_path_c)
        if ret != 0:
            raise QTLSException(ret)


class QTLSConnection:
    """
    Q-TLS connection wrapper.

    Example:
        conn = QTLSConnection(ctx)
        conn.set_fd(sock.fileno())
        conn.connect()
        conn.write(b'Hello!')
        data = conn.read(4096)
        conn.shutdown()
    """

    def __init__(self, ctx: QTLSContext, sock: Optional[socket.socket] = None):
        """
        Create a new Q-TLS connection.

        Args:
            ctx: Q-TLS context
            sock: Optional socket to wrap
        """
        self._conn = _lib.qtls_new(ctx._ctx)
        if not self._conn:
            raise QTLSException(QTLSError.ERROR_GENERIC, "Failed to create Q-TLS connection")
        self._ctx = ctx
        self._socket = sock
        if sock:
            ret = _lib.qtls_set_fd(self._conn, sock.fileno())
            if ret != 0:
                raise QTLSException(ret)

    def __del__(self):
        """Free the connection"""
        if hasattr(self, '_conn') and self._conn:
            _lib.qtls_free(self._conn)

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        try:
            self.shutdown()
        except:
            pass

    def set_fd(self, fd: int) -> None:
        """
        Set the file descriptor for the connection.

        Args:
            fd: Socket file descriptor
        """
        ret = _lib.qtls_set_fd(self._conn, fd)
        if ret != 0:
            raise QTLSException(ret)

    def connect(self) -> None:
        """Perform client-side handshake"""
        ret = _lib.qtls_connect(self._conn)
        if ret != 0:
            raise QTLSException(ret)

    def accept(self) -> None:
        """Perform server-side handshake"""
        ret = _lib.qtls_accept(self._conn)
        if ret != 0:
            raise QTLSException(ret)

    def read(self, num: int = 4096) -> bytes:
        """
        Read encrypted data from connection.

        Args:
            num: Maximum bytes to read

        Returns:
            Decrypted data as bytes
        """
        buf = ctypes.create_string_buffer(num)
        n = _lib.qtls_read(self._conn, buf, num)
        if n < 0:
            raise QTLSException(n)
        return buf.raw[:n]

    def write(self, data: bytes) -> int:
        """
        Write encrypted data to connection.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        n = _lib.qtls_write(self._conn, data, len(data))
        if n < 0:
            raise QTLSException(n)
        return n

    def shutdown(self) -> None:
        """Shutdown the connection"""
        ret = _lib.qtls_shutdown(self._conn)
        if ret != 0 and ret != QTLSError.ERROR_ZERO_RETURN:
            raise QTLSException(ret)

    def verify_peer_certificate(self) -> bool:
        """
        Verify peer certificate.

        Returns:
            True if verified, False otherwise
        """
        return _lib.qtls_verify_peer_certificate(self._conn) == 1


class QTLSServer:
    """
    High-level Q-TLS server.

    Example:
        ctx = QTLSContext(mode=QTLS_SERVER_MODE)
        ctx.use_certificate_file('/etc/qtls/server-cert.pem')
        ctx.use_private_key_file('/etc/qtls/server-key.pem')
        ctx.set_options(QTLS_OP_HYBRID_MODE)

        server = QTLSServer(ctx, '0.0.0.0', 8443)
        for conn in server.accept_connections():
            data = conn.read(4096)
            conn.write(b'Echo: ' + data)
            conn.shutdown()
    """

    def __init__(self, ctx: QTLSContext, host: str = '0.0.0.0', port: int = 8443):
        """
        Create a Q-TLS server.

        Args:
            ctx: Q-TLS context (must be in server mode)
            host: Bind address
            port: Bind port
        """
        if ctx._mode != QTLS_SERVER_MODE:
            raise ValueError("Context must be in server mode")

        self._ctx = ctx
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, port))
        self._socket.listen(5)

    def __del__(self):
        """Close the server socket"""
        if hasattr(self, '_socket'):
            self._socket.close()

    def accept_connections(self):
        """
        Accept incoming connections.

        Yields:
            QTLSConnection objects for each accepted connection
        """
        while True:
            client_sock, addr = self._socket.accept()
            try:
                conn = QTLSConnection(self._ctx, client_sock)
                conn.accept()
                yield conn
            except QTLSException as e:
                print(f"Handshake failed: {e}")
                client_sock.close()
                continue

    def close(self):
        """Close the server"""
        self._socket.close()


class QTLSClient:
    """
    High-level Q-TLS client.

    Example:
        ctx = QTLSContext(mode=QTLS_CLIENT_MODE)
        ctx.load_verify_locations('/etc/qtls/ca-bundle.pem')
        ctx.set_options(QTLS_OP_HYBRID_MODE)

        client = QTLSClient(ctx)
        client.connect('server.example.com', 8443)
        client.write(b'Hello Q-TLS!')
        response = client.read(4096)
        client.shutdown()
    """

    def __init__(self, ctx: QTLSContext):
        """
        Create a Q-TLS client.

        Args:
            ctx: Q-TLS context (must be in client mode)
        """
        if ctx._mode != QTLS_CLIENT_MODE:
            raise ValueError("Context must be in client mode")

        self._ctx = ctx
        self._socket = None
        self._conn = None

    def connect(self, host: str, port: int = 8443) -> None:
        """
        Connect to server.

        Args:
            host: Server hostname or IP
            port: Server port
        """
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((host, port))

        self._conn = QTLSConnection(self._ctx, self._socket)
        self._conn.connect()

    def read(self, num: int = 4096) -> bytes:
        """Read data from server"""
        if not self._conn:
            raise RuntimeError("Not connected")
        return self._conn.read(num)

    def write(self, data: bytes) -> int:
        """Write data to server"""
        if not self._conn:
            raise RuntimeError("Not connected")
        return self._conn.write(data)

    def shutdown(self) -> None:
        """Shutdown the connection"""
        if self._conn:
            self._conn.shutdown()
        if self._socket:
            self._socket.close()

    def verify_peer_certificate(self) -> bool:
        """Verify server certificate"""
        if not self._conn:
            raise RuntimeError("Not connected")
        return self._conn.verify_peer_certificate()


class QTLSKyber:
    """
    KYBER1024 post-quantum key encapsulation wrapper.

    Example:
        # Server side
        key = QTLSKyber()
        key.keygen()
        public_key = key.get_public_key()
        # ... send public_key to client ...
        # ... receive ciphertext from client ...
        key.set_ciphertext(ciphertext)
        shared_secret = key.decapsulate()

        # Client side
        key = QTLSKyber()
        key.set_public_key(server_public_key)
        shared_secret = key.encapsulate()
        ciphertext = key.get_ciphertext()
        # ... send ciphertext to server ...
    """

    def __init__(self):
        """Create a new KYBER key structure"""
        self._key = QTLS_KYBER_KEY()

    def keygen(self) -> None:
        """Generate a new KYBER1024 keypair"""
        ret = _lib.qtls_kyber_keygen(ctypes.byref(self._key))
        if ret != 0:
            raise QTLSException(ret)

    def encapsulate(self) -> bytes:
        """
        Perform KYBER encapsulation (client side).

        Returns:
            Shared secret
        """
        ret = _lib.qtls_kyber_encapsulate(ctypes.byref(self._key))
        if ret != 0:
            raise QTLSException(ret)
        return bytes(self._key.shared_secret)

    def decapsulate(self) -> bytes:
        """
        Perform KYBER decapsulation (server side).

        Returns:
            Shared secret
        """
        ret = _lib.qtls_kyber_decapsulate(ctypes.byref(self._key))
        if ret != 0:
            raise QTLSException(ret)
        return bytes(self._key.shared_secret)

    def get_public_key(self) -> bytes:
        """Get the public key"""
        return bytes(self._key.public_key)

    def set_public_key(self, public_key: bytes) -> None:
        """Set the public key"""
        if len(public_key) != QTLS_KYBER1024_PUBLIC_KEY_BYTES:
            raise ValueError(f"Public key must be {QTLS_KYBER1024_PUBLIC_KEY_BYTES} bytes")
        ctypes.memmove(self._key.public_key, public_key, len(public_key))

    def get_ciphertext(self) -> bytes:
        """Get the ciphertext"""
        return bytes(self._key.ciphertext)

    def set_ciphertext(self, ciphertext: bytes) -> None:
        """Set the ciphertext"""
        if len(ciphertext) != QTLS_KYBER1024_CIPHERTEXT_BYTES:
            raise ValueError(f"Ciphertext must be {QTLS_KYBER1024_CIPHERTEXT_BYTES} bytes")
        ctypes.memmove(self._key.ciphertext, ciphertext, len(ciphertext))


class QTLSDilithium:
    """
    DILITHIUM3 post-quantum digital signature wrapper.

    Example:
        # Generate keypair
        key = QTLSDilithium()
        key.keygen()
        public_key = key.get_public_key()

        # Sign message
        message = b'Hello, quantum world!'
        signature = key.sign(message)

        # Verify signature
        key2 = QTLSDilithium()
        key2.set_public_key(public_key)
        is_valid = key2.verify(message, signature)
    """

    def __init__(self):
        """Create a new DILITHIUM key structure"""
        self._key = QTLS_DILITHIUM_KEY()

    def keygen(self) -> None:
        """Generate a new DILITHIUM3 keypair"""
        ret = _lib.qtls_dilithium_keygen(ctypes.byref(self._key))
        if ret != 0:
            raise QTLSException(ret)

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with DILITHIUM3.

        Args:
            message: Message to sign

        Returns:
            Signature bytes
        """
        sig = ctypes.create_string_buffer(QTLS_DILITHIUM3_SIGNATURE_BYTES)
        sig_len = ctypes.c_size_t(QTLS_DILITHIUM3_SIGNATURE_BYTES)

        ret = _lib.qtls_dilithium_sign(
            ctypes.byref(self._key),
            message,
            len(message),
            sig,
            ctypes.byref(sig_len)
        )
        if ret != 0:
            raise QTLSException(ret)

        return sig.raw[:sig_len.value]

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a DILITHIUM3 signature.

        Args:
            message: Original message
            signature: Signature to verify

        Returns:
            True if valid, False otherwise
        """
        ret = _lib.qtls_dilithium_verify(
            ctypes.byref(self._key),
            message,
            len(message),
            signature,
            len(signature)
        )
        return ret == 1

    def get_public_key(self) -> bytes:
        """Get the public key"""
        return bytes(self._key.public_key)

    def set_public_key(self, public_key: bytes) -> None:
        """Set the public key"""
        if len(public_key) != QTLS_DILITHIUM3_PUBLIC_KEY_BYTES:
            raise ValueError(f"Public key must be {QTLS_DILITHIUM3_PUBLIC_KEY_BYTES} bytes")
        ctypes.memmove(self._key.public_key, public_key, len(public_key))


def get_version() -> str:
    """Get Q-TLS library version"""
    return _lib.qtls_version().decode('utf-8')


__all__ = [
    # Version
    'QTLS_VERSION_STRING',
    'get_version',

    # Modes
    'QTLS_CLIENT_MODE',
    'QTLS_SERVER_MODE',

    # Options
    'QTLS_OP_HYBRID_MODE',
    'QTLS_OP_PQC_ONLY',
    'QTLS_OP_CLASSICAL_ONLY',

    # Verification
    'QTLS_VERIFY_NONE',
    'QTLS_VERIFY_PEER',
    'QTLS_VERIFY_FAIL_IF_NO_PEER_CERT',

    # File types
    'QTLS_FILETYPE_PEM',
    'QTLS_FILETYPE_ASN1',

    # Classes
    'QTLSContext',
    'QTLSConnection',
    'QTLSServer',
    'QTLSClient',
    'QTLSKyber',
    'QTLSDilithium',

    # Enums
    'QTLSAlgorithm',
    'QTLSError',

    # Exceptions
    'QTLSException',
]
