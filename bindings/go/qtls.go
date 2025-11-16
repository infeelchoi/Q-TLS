// Package qtls provides Go bindings for Q-TLS (Quantum-Resistant Transport Security Layer).
//
// Q-TLS is a production-ready implementation of TLS with post-quantum cryptography (PQC) support.
// It provides hybrid cryptographic protection combining classical algorithms with NIST-standardized
// PQC algorithms (KYBER1024 and DILITHIUM3).
//
// Example usage:
//
//	// Server
//	config := &qtls.Config{
//		Certificates: []qtls.Certificate{cert},
//		HybridMode:   true,
//	}
//	listener, err := qtls.Listen("tcp", ":8443", config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	for {
//		conn, err := listener.Accept()
//		if err != nil {
//			log.Println(err)
//			continue
//		}
//		go handleConnection(conn)
//	}
//
//	// Client
//	config := &qtls.Config{
//		RootCAs:    certPool,
//		HybridMode: true,
//	}
//	conn, err := qtls.Dial("tcp", "server.example.com:8443", config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer conn.Close()
//
// Copyright 2025 QSIGN Project
// Licensed under the Apache License, Version 2.0
package qtls

/*
#cgo LDFLAGS: -lqtls -loqs -lssl -lcrypto
#cgo CFLAGS: -I/usr/local/include -I../../include

#include <stdlib.h>
#include <qtls/qtls.h>
*/
import "C"
import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"
)

// Version information
const (
	VersionMajor = 1
	VersionMinor = 0
	VersionPatch = 0
	Version      = "1.0.0"
)

// Operating modes
const (
	ClientMode = C.QTLS_CLIENT_MODE
	ServerMode = C.QTLS_SERVER_MODE
)

// Context options
const (
	OpNoSSLv2        = C.QTLS_OP_NO_SSLv2
	OpNoSSLv3        = C.QTLS_OP_NO_SSLv3
	OpNoTLSv1        = C.QTLS_OP_NO_TLSv1
	OpNoTLSv1_1      = C.QTLS_OP_NO_TLSv1_1
	OpNoTLSv1_2      = C.QTLS_OP_NO_TLSv1_2
	OpHybridMode     = C.QTLS_OP_HYBRID_MODE
	OpPQCOnly        = C.QTLS_OP_PQC_ONLY
	OpClassicalOnly  = C.QTLS_OP_CLASSICAL_ONLY
)

// Verification modes
const (
	VerifyNone              = C.QTLS_VERIFY_NONE
	VerifyPeer              = C.QTLS_VERIFY_PEER
	VerifyFailIfNoPeerCert  = C.QTLS_VERIFY_FAIL_IF_NO_PEER_CERT
	VerifyClientOnce        = C.QTLS_VERIFY_CLIENT_ONCE
)

// File types
const (
	FileTypePEM  = C.QTLS_FILETYPE_PEM
	FileTypeASN1 = C.QTLS_FILETYPE_ASN1
)

// Error codes
const (
	ErrSuccess            = 0
	ErrGeneric            = -1
	ErrNullPointer        = -2
	ErrInvalidArgument    = -3
	ErrOutOfMemory        = -4
	ErrSyscall            = -5
	ErrWantRead           = -6
	ErrWantWrite          = -7
	ErrZeroReturn         = -8
	ErrHandshakeFailed    = -200
	ErrCertVerifyFailed   = -202
	ErrHSMNotAvailable    = -300
)

// Common errors
var (
	ErrContextNil      = errors.New("qtls: context is nil")
	ErrConnectionNil   = errors.New("qtls: connection is nil")
	ErrConnectionClosed = errors.New("qtls: connection closed")
	ErrTimeout         = errors.New("qtls: i/o timeout")
	ErrBadCertificate  = errors.New("qtls: bad certificate")
)

// QTLSError wraps Q-TLS error codes
type QTLSError struct {
	Code    int
	Message string
}

func (e *QTLSError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("qtls: %s (code %d)", e.Message, e.Code)
	}
	return fmt.Sprintf("qtls: error code %d", e.Code)
}

// newError creates a new QTLSError from a C error code
func newError(code C.int) error {
	if code == 0 {
		return nil
	}
	cstr := C.qtls_get_error_string(code)
	msg := C.GoString(cstr)
	return &QTLSError{
		Code:    int(code),
		Message: msg,
	}
}

// Certificate represents a Q-TLS certificate
type Certificate struct {
	Certificate [][]byte
	PrivateKey  interface{}
	Leaf        *x509.Certificate
}

// Config is the configuration for Q-TLS connections
type Config struct {
	// Certificates contains one or more certificate chains to present to the other side
	Certificates []Certificate

	// RootCAs defines the set of root certificate authorities
	RootCAs *x509.CertPool

	// ClientCAs defines the set of root certificate authorities for client verification
	ClientCAs *x509.CertPool

	// ServerName is the server name for SNI
	ServerName string

	// HybridMode enables hybrid post-quantum cryptography
	HybridMode bool

	// PQCOnly uses only post-quantum algorithms (experimental)
	PQCOnly bool

	// ClassicalOnly uses only classical algorithms
	ClassicalOnly bool

	// InsecureSkipVerify controls whether to skip certificate verification
	InsecureSkipVerify bool

	// ClientAuth determines the server's policy for client authentication
	ClientAuth ClientAuthType

	// Time returns the current time. If nil, time.Now is used.
	Time func() time.Time

	// HSMKeyURI is the PKCS#11 URI for HSM-stored keys
	HSMKeyURI string

	// CertificateFile is the path to the certificate file
	CertificateFile string

	// PrivateKeyFile is the path to the private key file
	PrivateKeyFile string

	// CAFile is the path to the CA bundle file
	CAFile string

	// CAPath is the path to the CA directory
	CAPath string
}

// ClientAuthType declares the policy for client authentication
type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// context wraps the C QTLS_CTX
type context struct {
	ctx  *C.QTLS_CTX
	mode int
	mu   sync.Mutex
}

// newContext creates a new Q-TLS context
func newContext(mode int) (*context, error) {
	cctx := C.qtls_ctx_new(C.int(mode))
	if cctx == nil {
		return nil, errors.New("qtls: failed to create context")
	}

	ctx := &context{
		ctx:  cctx,
		mode: mode,
	}

	return ctx, nil
}

// Free frees the context
func (c *context) Free() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx != nil {
		C.qtls_ctx_free(c.ctx)
		c.ctx = nil
	}
}

// SetOptions sets context options
func (c *context) SetOptions(options uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ret := C.qtls_ctx_set_options(c.ctx, C.uint32_t(options))
	return newError(ret)
}

// SetVerifyMode sets certificate verification mode
func (c *context) SetVerifyMode(mode int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ret := C.qtls_ctx_set_verify_mode(c.ctx, C.int(mode), nil)
	return newError(ret)
}

// UseCertificateFile loads a certificate from file
func (c *context) UseCertificateFile(file string, fileType int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfile := C.CString(file)
	defer C.free(unsafe.Pointer(cfile))

	ret := C.qtls_ctx_use_certificate_file(c.ctx, cfile, C.int(fileType))
	return newError(ret)
}

// UsePrivateKeyFile loads a private key from file
func (c *context) UsePrivateKeyFile(file string, fileType int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfile := C.CString(file)
	defer C.free(unsafe.Pointer(cfile))

	ret := C.qtls_ctx_use_private_key_file(c.ctx, cfile, C.int(fileType))
	return newError(ret)
}

// UseHSMKey loads a private key from HSM
func (c *context) UseHSMKey(uri string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	curi := C.CString(uri)
	defer C.free(unsafe.Pointer(curi))

	ret := C.qtls_ctx_use_hsm_key(c.ctx, curi)
	return newError(ret)
}

// LoadVerifyLocations loads CA certificates
func (c *context) LoadVerifyLocations(file, path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var cfile, cpath *C.char
	if file != "" {
		cfile = C.CString(file)
		defer C.free(unsafe.Pointer(cfile))
	}
	if path != "" {
		cpath = C.CString(path)
		defer C.free(unsafe.Pointer(cpath))
	}

	ret := C.qtls_ctx_load_verify_locations(c.ctx, cfile, cpath)
	return newError(ret)
}

// Conn is a Q-TLS network connection implementing net.Conn
type Conn struct {
	conn      *C.QTLS_CONNECTION
	ctx       *context
	netConn   net.Conn
	mu        sync.Mutex
	readMu    sync.Mutex
	writeMu   sync.Mutex
	handshook bool
}

// newConn creates a new Q-TLS connection
func newConn(ctx *context, netConn net.Conn) (*Conn, error) {
	if ctx == nil || ctx.ctx == nil {
		return nil, ErrContextNil
	}

	cconn := C.qtls_new(ctx.ctx)
	if cconn == nil {
		return nil, errors.New("qtls: failed to create connection")
	}

	conn := &Conn{
		conn:    cconn,
		ctx:     ctx,
		netConn: netConn,
	}

	// Set file descriptor
	if tcpConn, ok := netConn.(*net.TCPConn); ok {
		rawConn, err := tcpConn.SyscallConn()
		if err != nil {
			return nil, err
		}

		var fd int
		err = rawConn.Control(func(descriptor uintptr) {
			fd = int(descriptor)
		})
		if err != nil {
			return nil, err
		}

		ret := C.qtls_set_fd(cconn, C.int(fd))
		if ret != 0 {
			C.qtls_free(cconn)
			return nil, newError(ret)
		}
	}

	return conn, nil
}

// Handshake runs the client or server handshake
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the client or server handshake with context
func (c *Conn) HandshakeContext(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.handshook {
		return nil
	}

	var ret C.int
	if c.ctx.mode == ClientMode {
		ret = C.qtls_connect(c.conn)
	} else {
		ret = C.qtls_accept(c.conn)
	}

	if ret != 0 {
		return newError(ret)
	}

	c.handshook = true
	return nil
}

// Read reads data from the connection
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if !c.handshook {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}

	if len(b) == 0 {
		return 0, nil
	}

	n := C.qtls_read(c.conn, unsafe.Pointer(&b[0]), C.int(len(b)))
	if n < 0 {
		if n == C.int(ErrZeroReturn) {
			return 0, io.EOF
		}
		return 0, newError(C.int(n))
	}

	return int(n), nil
}

// Write writes data to the connection
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.handshook {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}

	if len(b) == 0 {
		return 0, nil
	}

	n := C.qtls_write(c.conn, unsafe.Pointer(&b[0]), C.int(len(b)))
	if n < 0 {
		return 0, newError(C.int(n))
	}

	return int(n), nil
}

// Close closes the connection
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		C.qtls_shutdown(c.conn)
		C.qtls_free(c.conn)
		c.conn = nil
	}

	if c.netConn != nil {
		return c.netConn.Close()
	}

	return nil
}

// LocalAddr returns the local network address
func (c *Conn) LocalAddr() net.Addr {
	return c.netConn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (c *Conn) RemoteAddr() net.Addr {
	return c.netConn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines
func (c *Conn) SetDeadline(t time.Time) error {
	return c.netConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.netConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.netConn.SetWriteDeadline(t)
}

// VerifyPeerCertificate verifies the peer certificate
func (c *Conn) VerifyPeerCertificate() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	ret := C.qtls_verify_peer_certificate(c.conn)
	return ret == 1
}

// ConnectionState returns basic connection information
type ConnectionState struct {
	HandshakeComplete bool
	PeerCertificates  []*x509.Certificate
	VerifiedChains    [][]*x509.Certificate
	ServerName        string
}

// ConnectionState returns the connection state
func (c *Conn) ConnectionState() ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()

	return ConnectionState{
		HandshakeComplete: c.handshook,
	}
}

// Listener is a Q-TLS network listener
type Listener struct {
	listener net.Listener
	config   *Config
	ctx      *context
}

// Listen creates a Q-TLS listener
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil {
		config = &Config{HybridMode: true}
	}

	listener, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	ctx, err := newContext(ServerMode)
	if err != nil {
		listener.Close()
		return nil, err
	}

	// Apply configuration
	if err := applyConfig(ctx, config); err != nil {
		ctx.Free()
		listener.Close()
		return nil, err
	}

	return &Listener{
		listener: listener,
		config:   config,
		ctx:      ctx,
	}, nil
}

// Accept waits for and returns the next connection
func (l *Listener) Accept() (net.Conn, error) {
	netConn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	conn, err := newConn(l.ctx, netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}

	return conn, nil
}

// Close closes the listener
func (l *Listener) Close() error {
	l.ctx.Free()
	return l.listener.Close()
}

// Addr returns the listener's network address
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Dial connects to the given network address
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialContext(context.Background(), network, addr, config)
}

// DialContext connects to the given network address with context
func DialContext(ctx context.Context, network, addr string, config *Config) (*Conn, error) {
	if config == nil {
		config = &Config{HybridMode: true}
	}

	netConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	qtlsCtx, err := newContext(ClientMode)
	if err != nil {
		netConn.Close()
		return nil, err
	}

	// Apply configuration
	if err := applyConfig(qtlsCtx, config); err != nil {
		qtlsCtx.Free()
		netConn.Close()
		return nil, err
	}

	conn, err := newConn(qtlsCtx, netConn)
	if err != nil {
		qtlsCtx.Free()
		netConn.Close()
		return nil, err
	}

	return conn, nil
}

// applyConfig applies a Config to a context
func applyConfig(ctx *context, config *Config) error {
	// Set mode flags
	var options uint32
	if config.HybridMode {
		options |= OpHybridMode
	}
	if config.PQCOnly {
		options |= OpPQCOnly
	}
	if config.ClassicalOnly {
		options |= OpClassicalOnly
	}

	if options != 0 {
		if err := ctx.SetOptions(options); err != nil {
			return err
		}
	}

	// Load certificate
	if config.CertificateFile != "" {
		if err := ctx.UseCertificateFile(config.CertificateFile, FileTypePEM); err != nil {
			return err
		}
	}

	// Load private key
	if config.PrivateKeyFile != "" {
		if err := ctx.UsePrivateKeyFile(config.PrivateKeyFile, FileTypePEM); err != nil {
			return err
		}
	}

	// Load HSM key
	if config.HSMKeyURI != "" {
		if err := ctx.UseHSMKey(config.HSMKeyURI); err != nil {
			return err
		}
	}

	// Load CA certificates
	if config.CAFile != "" || config.CAPath != "" {
		if err := ctx.LoadVerifyLocations(config.CAFile, config.CAPath); err != nil {
			return err
		}
	}

	// Set verification mode
	if ctx.mode == ClientMode {
		if !config.InsecureSkipVerify {
			if err := ctx.SetVerifyMode(VerifyPeer | VerifyFailIfNoPeerCert); err != nil {
				return err
			}
		}
	} else {
		// Server mode
		var verifyMode int
		switch config.ClientAuth {
		case NoClientCert:
			verifyMode = VerifyNone
		case RequestClientCert, VerifyClientCertIfGiven:
			verifyMode = VerifyPeer
		case RequireAnyClientCert, RequireAndVerifyClientCert:
			verifyMode = VerifyPeer | VerifyFailIfNoPeerCert
		}
		if verifyMode != 0 {
			if err := ctx.SetVerifyMode(verifyMode); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetVersion returns the Q-TLS library version
func GetVersion() string {
	cstr := C.qtls_version()
	return C.GoString(cstr)
}

// KyberKey represents a KYBER1024 key
type KyberKey struct {
	key C.QTLS_KYBER_KEY
}

// NewKyberKey creates a new KYBER key
func NewKyberKey() *KyberKey {
	return &KyberKey{}
}

// Keygen generates a KYBER1024 keypair
func (k *KyberKey) Keygen() error {
	ret := C.qtls_kyber_keygen(&k.key)
	return newError(ret)
}

// Encapsulate performs KYBER encapsulation
func (k *KyberKey) Encapsulate() ([]byte, error) {
	ret := C.qtls_kyber_encapsulate(&k.key)
	if ret != 0 {
		return nil, newError(ret)
	}
	return C.GoBytes(unsafe.Pointer(&k.key.shared_secret[0]), C.QTLS_KYBER1024_SHARED_SECRET_BYTES), nil
}

// Decapsulate performs KYBER decapsulation
func (k *KyberKey) Decapsulate() ([]byte, error) {
	ret := C.qtls_kyber_decapsulate(&k.key)
	if ret != 0 {
		return nil, newError(ret)
	}
	return C.GoBytes(unsafe.Pointer(&k.key.shared_secret[0]), C.QTLS_KYBER1024_SHARED_SECRET_BYTES), nil
}

// PublicKey returns the public key
func (k *KyberKey) PublicKey() []byte {
	return C.GoBytes(unsafe.Pointer(&k.key.public_key[0]), C.QTLS_KYBER1024_PUBLIC_KEY_BYTES)
}

// SetPublicKey sets the public key
func (k *KyberKey) SetPublicKey(pk []byte) error {
	if len(pk) != C.QTLS_KYBER1024_PUBLIC_KEY_BYTES {
		return errors.New("qtls: invalid public key size")
	}
	C.memcpy(unsafe.Pointer(&k.key.public_key[0]), unsafe.Pointer(&pk[0]), C.QTLS_KYBER1024_PUBLIC_KEY_BYTES)
	return nil
}

// Ciphertext returns the ciphertext
func (k *KyberKey) Ciphertext() []byte {
	return C.GoBytes(unsafe.Pointer(&k.key.ciphertext[0]), C.QTLS_KYBER1024_CIPHERTEXT_BYTES)
}

// SetCiphertext sets the ciphertext
func (k *KyberKey) SetCiphertext(ct []byte) error {
	if len(ct) != C.QTLS_KYBER1024_CIPHERTEXT_BYTES {
		return errors.New("qtls: invalid ciphertext size")
	}
	C.memcpy(unsafe.Pointer(&k.key.ciphertext[0]), unsafe.Pointer(&ct[0]), C.QTLS_KYBER1024_CIPHERTEXT_BYTES)
	return nil
}

// DilithiumKey represents a DILITHIUM3 key
type DilithiumKey struct {
	key C.QTLS_DILITHIUM_KEY
}

// NewDilithiumKey creates a new DILITHIUM key
func NewDilithiumKey() *DilithiumKey {
	return &DilithiumKey{}
}

// Keygen generates a DILITHIUM3 keypair
func (d *DilithiumKey) Keygen() error {
	ret := C.qtls_dilithium_keygen(&d.key)
	return newError(ret)
}

// Sign signs a message
func (d *DilithiumKey) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, C.QTLS_DILITHIUM3_SIGNATURE_BYTES)
	var sigLen C.size_t = C.QTLS_DILITHIUM3_SIGNATURE_BYTES

	ret := C.qtls_dilithium_sign(
		&d.key,
		unsafe.Pointer(&msg[0]),
		C.size_t(len(msg)),
		unsafe.Pointer(&sig[0]),
		&sigLen,
	)

	if ret != 0 {
		return nil, newError(ret)
	}

	return sig[:sigLen], nil
}

// Verify verifies a signature
func (d *DilithiumKey) Verify(msg, sig []byte) (bool, error) {
	ret := C.qtls_dilithium_verify(
		&d.key,
		unsafe.Pointer(&msg[0]),
		C.size_t(len(msg)),
		unsafe.Pointer(&sig[0]),
		C.size_t(len(sig)),
	)

	if ret == 1 {
		return true, nil
	} else if ret == 0 {
		return false, nil
	}
	return false, newError(ret)
}

// PublicKey returns the public key
func (d *DilithiumKey) PublicKey() []byte {
	return C.GoBytes(unsafe.Pointer(&d.key.public_key[0]), C.QTLS_DILITHIUM3_PUBLIC_KEY_BYTES)
}

// SetPublicKey sets the public key
func (d *DilithiumKey) SetPublicKey(pk []byte) error {
	if len(pk) != C.QTLS_DILITHIUM3_PUBLIC_KEY_BYTES {
		return errors.New("qtls: invalid public key size")
	}
	C.memcpy(unsafe.Pointer(&d.key.public_key[0]), unsafe.Pointer(&pk[0]), C.QTLS_DILITHIUM3_PUBLIC_KEY_BYTES)
	return nil
}
