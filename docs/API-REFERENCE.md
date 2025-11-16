# Q-TLS API 레퍼런스

## 목차

1. [개요](#개요)
2. [C API](#c-api)
3. [Python 바인딩](#python-바인딩)
4. [Node.js 바인딩](#nodejs-바인딩)
5. [Go 바인딩](#go-바인딩)
6. [에러 코드](#에러-코드)

---

## 개요

Q-TLS는 다양한 프로그래밍 언어에서 사용할 수 있는 API를 제공합니다:

- **C API**: 네이티브 C 라이브러리 API
- **Python**: ctypes 기반 바인딩
- **Node.js**: N-API 기반 네이티브 애드온
- **Go**: CGO 기반 바인딩

### API 설계 원칙

1. **간결성**: 최소한의 함수로 최대 기능 제공
2. **안전성**: 메모리 안전성 및 에러 처리
3. **성능**: 제로 카피 및 최적화된 구현
4. **호환성**: OpenSSL 유사 API 디자인

---

## C API

### 컨텍스트 관리

#### qtls_ctx_new()

```c
QTLS_CTX *qtls_ctx_new(int mode);
```

**설명**: 새 Q-TLS 컨텍스트를 생성합니다.

**매개변수**:
- `mode`: `QTLS_CLIENT_MODE` 또는 `QTLS_SERVER_MODE`

**반환값**:
- 성공: 새로 생성된 컨텍스트 포인터
- 실패: `NULL`

**예제**:
```c
#include <qtls/qtls.h>

int main() {
    QTLS_CTX *ctx = qtls_ctx_new(QTLS_SERVER_MODE);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    // 컨텍스트 사용...

    qtls_ctx_free(ctx);
    return 0;
}
```

#### qtls_ctx_free()

```c
void qtls_ctx_free(QTLS_CTX *ctx);
```

**설명**: Q-TLS 컨텍스트를 해제합니다.

**매개변수**:
- `ctx`: 해제할 컨텍스트

**반환값**: 없음

**주의**: 컨텍스트와 연결된 모든 리소스가 해제됩니다.

#### qtls_ctx_set_options()

```c
int qtls_ctx_set_options(QTLS_CTX *ctx, uint32_t options);
```

**설명**: 컨텍스트 옵션을 설정합니다.

**매개변수**:
- `ctx`: 컨텍스트
- `options`: 옵션 플래그 (비트마스크)

**옵션**:
- `QTLS_OP_HYBRID_MODE`: 하이브리드 PQC 모드 활성화
- `QTLS_OP_PQC_ONLY`: PQC 전용 모드 (실험적)
- `QTLS_OP_CLASSICAL_ONLY`: 기존 암호화만 사용
- `QTLS_OP_NO_TLSv1_2`: TLS 1.2 비활성화

**반환값**:
- `QTLS_SUCCESS` (0): 성공
- `QTLS_ERROR_INVALID_ARGUMENT`: 잘못된 옵션

**예제**:
```c
// 하이브리드 모드 활성화
qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE);

// 여러 옵션 조합
qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE | QTLS_OP_NO_TLSv1_2);
```

#### qtls_ctx_get_options()

```c
uint32_t qtls_ctx_get_options(QTLS_CTX *ctx);
```

**설명**: 현재 설정된 옵션을 가져옵니다.

**매개변수**:
- `ctx`: 컨텍스트

**반환값**: 현재 옵션 플래그

**예제**:
```c
uint32_t options = qtls_ctx_get_options(ctx);
if (options & QTLS_OP_HYBRID_MODE) {
    printf("Hybrid mode is enabled\n");
}
```

### 인증서 관리

#### qtls_ctx_use_certificate_file()

```c
int qtls_ctx_use_certificate_file(QTLS_CTX *ctx, const char *file, int type);
```

**설명**: 파일에서 인증서를 로드합니다.

**매개변수**:
- `ctx`: 컨텍스트
- `file`: 인증서 파일 경로
- `type`: `QTLS_FILETYPE_PEM` 또는 `QTLS_FILETYPE_ASN1`

**반환값**:
- `QTLS_SUCCESS`: 성공
- `QTLS_ERROR_NULL_POINTER`: NULL 포인터
- `QTLS_ERROR_SYSCALL`: 파일 읽기 실패

**예제**:
```c
int ret = qtls_ctx_use_certificate_file(ctx,
    "/etc/qtls/certs/server-cert.pem",
    QTLS_FILETYPE_PEM);
if (ret != QTLS_SUCCESS) {
    fprintf(stderr, "Failed to load certificate: %s\n",
        qtls_get_error_string(ret));
    return 1;
}
```

#### qtls_ctx_use_private_key_file()

```c
int qtls_ctx_use_private_key_file(QTLS_CTX *ctx, const char *file, int type);
```

**설명**: 파일에서 개인키를 로드합니다.

**매개변수**:
- `ctx`: 컨텍스트
- `file`: 개인키 파일 경로
- `type`: 파일 타입

**반환값**:
- `QTLS_SUCCESS`: 성공
- 음수: 에러 코드

**예제**:
```c
qtls_ctx_use_private_key_file(ctx,
    "/etc/qtls/certs/server-key.pem",
    QTLS_FILETYPE_PEM);
```

#### qtls_ctx_use_hsm_key()

```c
int qtls_ctx_use_hsm_key(QTLS_CTX *ctx, const char *uri);
```

**설명**: HSM에서 개인키를 로드합니다 (PKCS#11 URI 사용).

**매개변수**:
- `ctx`: 컨텍스트
- `uri`: PKCS#11 URI (예: `"pkcs11:token=luna;object=mykey"`)

**반환값**:
- `QTLS_SUCCESS`: 성공
- `QTLS_ERROR_HSM_NOT_AVAILABLE`: HSM 연결 실패
- `QTLS_ERROR_HSM_KEY_NOT_FOUND`: 키를 찾을 수 없음

**예제**:
```c
// HSM 초기화
qtls_hsm_init("/usr/lib/libCryptoki2_64.so");
qtls_hsm_login("qtls-server", "hsm_pin");

// HSM 키 사용
qtls_ctx_use_hsm_key(ctx,
    "pkcs11:token=qtls-server;object=server-dilithium3;type=private");
```

#### qtls_ctx_load_verify_locations()

```c
int qtls_ctx_load_verify_locations(QTLS_CTX *ctx,
                                     const char *file,
                                     const char *path);
```

**설명**: CA 인증서를 로드합니다.

**매개변수**:
- `ctx`: 컨텍스트
- `file`: CA 번들 파일 경로 (NULL 가능)
- `path`: CA 인증서 디렉토리 (NULL 가능)

**반환값**:
- `QTLS_SUCCESS`: 성공
- 음수: 에러 코드

**예제**:
```c
// CA 번들 파일 사용
qtls_ctx_load_verify_locations(ctx,
    "/etc/qtls/certs/ca-bundle.pem", NULL);

// CA 디렉토리 사용
qtls_ctx_load_verify_locations(ctx,
    NULL, "/etc/qtls/certs/ca/");

// 둘 다 사용
qtls_ctx_load_verify_locations(ctx,
    "/etc/qtls/certs/ca-bundle.pem",
    "/etc/qtls/certs/ca/");
```

#### qtls_ctx_set_verify_mode()

```c
int qtls_ctx_set_verify_mode(QTLS_CTX *ctx, int mode,
                               qtls_verify_callback callback);
```

**설명**: 인증서 검증 모드를 설정합니다.

**매개변수**:
- `ctx`: 컨텍스트
- `mode`: 검증 모드 플래그
- `callback`: 검증 콜백 함수 (선택사항)

**검증 모드**:
- `QTLS_VERIFY_NONE`: 검증 안 함
- `QTLS_VERIFY_PEER`: 피어 인증서 검증
- `QTLS_VERIFY_FAIL_IF_NO_PEER_CERT`: 피어 인증서 없으면 실패
- `QTLS_VERIFY_CLIENT_ONCE`: 클라이언트 인증서 한 번만 검증

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
// 검증 콜백 함수
int verify_callback(int preverify_ok, QTLS_X509 *x509_ctx) {
    if (!preverify_ok) {
        fprintf(stderr, "Certificate verification failed\n");
        return 0;
    }
    // 추가 검증 로직...
    return 1;
}

// 상호 TLS 설정
qtls_ctx_set_verify_mode(ctx,
    QTLS_VERIFY_PEER | QTLS_VERIFY_FAIL_IF_NO_PEER_CERT,
    verify_callback);
```

### 연결 관리

#### qtls_new()

```c
QTLS_CONNECTION *qtls_new(QTLS_CTX *ctx);
```

**설명**: 새 Q-TLS 연결을 생성합니다.

**매개변수**:
- `ctx`: 컨텍스트

**반환값**:
- 성공: 새 연결 포인터
- 실패: `NULL`

**예제**:
```c
QTLS_CONNECTION *conn = qtls_new(ctx);
if (!conn) {
    fprintf(stderr, "Failed to create connection\n");
    return 1;
}
```

#### qtls_free()

```c
void qtls_free(QTLS_CONNECTION *conn);
```

**설명**: Q-TLS 연결을 해제합니다.

**매개변수**:
- `conn`: 연결

**반환값**: 없음

**예제**:
```c
qtls_shutdown(conn);
qtls_free(conn);
```

#### qtls_set_fd()

```c
int qtls_set_fd(QTLS_CONNECTION *conn, int fd);
```

**설명**: 소켓 파일 디스크립터를 연결에 연결합니다.

**매개변수**:
- `conn`: 연결
- `fd`: 소켓 파일 디스크립터

**반환값**:
- `QTLS_SUCCESS`: 성공
- 음수: 에러 코드

**예제**:
```c
// 서버: 클라이언트 연결 수락
int client_fd = accept(listen_fd, NULL, NULL);
qtls_set_fd(conn, client_fd);

// 클라이언트: 서버 연결
int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
qtls_set_fd(conn, sock_fd);
```

#### qtls_get_fd()

```c
int qtls_get_fd(QTLS_CONNECTION *conn);
```

**설명**: 연결의 파일 디스크립터를 가져옵니다.

**매개변수**:
- `conn`: 연결

**반환값**:
- 파일 디스크립터 (>= 0)
- -1: 설정되지 않음

### 핸드셰이크

#### qtls_connect()

```c
int qtls_connect(QTLS_CONNECTION *conn);
```

**설명**: 클라이언트 측 핸드셰이크를 수행합니다.

**매개변수**:
- `conn`: 연결

**반환값**:
- `QTLS_SUCCESS`: 성공
- `QTLS_ERROR_WANT_READ`: 더 많은 데이터 필요 (재시도)
- `QTLS_ERROR_WANT_WRITE`: 쓰기 준비 필요 (재시도)
- `QTLS_ERROR_HANDSHAKE_FAILED`: 핸드셰이크 실패

**예제**:
```c
// 블로킹 모드
int ret = qtls_connect(conn);
if (ret != QTLS_SUCCESS) {
    fprintf(stderr, "Handshake failed: %s\n",
        qtls_get_error_string(ret));
    return 1;
}

// 논블로킹 모드
while (1) {
    int ret = qtls_connect(conn);
    if (ret == QTLS_SUCCESS) {
        break;
    } else if (ret == QTLS_ERROR_WANT_READ) {
        // select/poll로 읽기 대기
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(qtls_get_fd(conn), &readfds);
        select(qtls_get_fd(conn) + 1, &readfds, NULL, NULL, NULL);
    } else if (ret == QTLS_ERROR_WANT_WRITE) {
        // select/poll로 쓰기 대기
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(qtls_get_fd(conn), &writefds);
        select(qtls_get_fd(conn) + 1, NULL, &writefds, NULL, NULL);
    } else {
        fprintf(stderr, "Handshake failed\n");
        return 1;
    }
}
```

#### qtls_accept()

```c
int qtls_accept(QTLS_CONNECTION *conn);
```

**설명**: 서버 측 핸드셰이크를 수행합니다.

**매개변수**:
- `conn`: 연결

**반환값**: `qtls_connect()`와 동일

**예제**:
```c
int ret = qtls_accept(conn);
if (ret != QTLS_SUCCESS) {
    fprintf(stderr, "Handshake failed: %s\n",
        qtls_get_error_string(ret));
    return 1;
}
```

#### qtls_set_server_name()

```c
int qtls_set_server_name(QTLS_CONNECTION *conn, const char *hostname);
```

**설명**: SNI (Server Name Indication)를 설정합니다.

**매개변수**:
- `conn`: 연결
- `hostname`: 서버 호스트명

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
qtls_set_server_name(conn, "server.example.com");
qtls_connect(conn);
```

#### qtls_verify_peer_certificate()

```c
int qtls_verify_peer_certificate(QTLS_CONNECTION *conn);
```

**설명**: 피어 인증서를 검증합니다.

**매개변수**:
- `conn`: 연결

**반환값**:
- 1: 검증 성공
- 0: 검증 실패

**예제**:
```c
if (!qtls_verify_peer_certificate(conn)) {
    fprintf(stderr, "Certificate verification failed\n");
    qtls_shutdown(conn);
    qtls_free(conn);
    return 1;
}
```

### I/O 작업

#### qtls_read()

```c
int qtls_read(QTLS_CONNECTION *conn, void *buf, int num);
```

**설명**: 암호화된 연결에서 데이터를 읽습니다.

**매개변수**:
- `conn`: 연결
- `buf`: 데이터 버퍼
- `num`: 최대 읽을 바이트 수

**반환값**:
- 양수: 읽은 바이트 수
- 0: 연결 종료
- `QTLS_ERROR_WANT_READ`: 더 많은 데이터 필요
- `QTLS_ERROR_WANT_WRITE`: 쓰기 준비 필요
- 음수: 에러

**예제**:
```c
char buffer[4096];
int n = qtls_read(conn, buffer, sizeof(buffer));
if (n > 0) {
    printf("Received: %.*s\n", n, buffer);
} else if (n == 0) {
    printf("Connection closed\n");
} else {
    fprintf(stderr, "Read error: %s\n",
        qtls_get_error_string(n));
}
```

#### qtls_write()

```c
int qtls_write(QTLS_CONNECTION *conn, const void *buf, int num);
```

**설명**: 암호화된 연결에 데이터를 씁니다.

**매개변수**:
- `conn`: 연결
- `buf`: 데이터 버퍼
- `num`: 쓸 바이트 수

**반환값**:
- 양수: 쓴 바이트 수
- `QTLS_ERROR_WANT_READ`: 읽기 준비 필요
- `QTLS_ERROR_WANT_WRITE`: 더 많은 버퍼 공간 필요
- 음수: 에러

**예제**:
```c
const char *message = "Hello Q-TLS!";
int n = qtls_write(conn, message, strlen(message));
if (n != strlen(message)) {
    fprintf(stderr, "Write error\n");
}
```

#### qtls_pending()

```c
int qtls_pending(QTLS_CONNECTION *conn);
```

**설명**: 읽을 수 있는 대기 중인 바이트 수를 반환합니다.

**매개변수**:
- `conn`: 연결

**반환값**: 대기 중인 바이트 수

**예제**:
```c
int pending = qtls_pending(conn);
if (pending > 0) {
    char *buffer = malloc(pending);
    qtls_read(conn, buffer, pending);
    free(buffer);
}
```

#### qtls_shutdown()

```c
int qtls_shutdown(QTLS_CONNECTION *conn);
```

**설명**: 연결을 정상적으로 종료합니다.

**매개변수**:
- `conn`: 연결

**반환값**:
- `QTLS_SUCCESS`: 종료 완료
- `QTLS_ERROR_WANT_READ`: 더 많은 데이터 필요
- `QTLS_ERROR_WANT_WRITE`: 쓰기 준비 필요

**예제**:
```c
qtls_shutdown(conn);
close(qtls_get_fd(conn));
qtls_free(conn);
```

### 암호화 작업

#### qtls_kyber_keygen()

```c
int qtls_kyber_keygen(QTLS_KYBER_KEY *key);
```

**설명**: KYBER1024 키쌍을 생성합니다.

**매개변수**:
- `key`: KYBER 키 구조체

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
QTLS_KYBER_KEY key;
memset(&key, 0, sizeof(key));

int ret = qtls_kyber_keygen(&key);
if (ret != QTLS_SUCCESS) {
    fprintf(stderr, "Key generation failed\n");
    return 1;
}

// 공개키 사용
// key.public_key[QTLS_KYBER1024_PUBLIC_KEY_BYTES]
```

#### qtls_kyber_encapsulate()

```c
int qtls_kyber_encapsulate(QTLS_KYBER_KEY *key);
```

**설명**: KYBER1024 캡슐화를 수행합니다 (클라이언트 측).

**매개변수**:
- `key`: 공개키가 설정된 KYBER 키 구조체

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
QTLS_KYBER_KEY key;
memcpy(key.public_key, server_public_key, QTLS_KYBER1024_PUBLIC_KEY_BYTES);

int ret = qtls_kyber_encapsulate(&key);
if (ret == QTLS_SUCCESS) {
    // key.ciphertext: 서버로 전송
    // key.shared_secret: 키 유도에 사용
}
```

#### qtls_kyber_decapsulate()

```c
int qtls_kyber_decapsulate(QTLS_KYBER_KEY *key);
```

**설명**: KYBER1024 역캡슐화를 수행합니다 (서버 측).

**매개변수**:
- `key`: 비밀키와 암호문이 설정된 KYBER 키 구조체

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
QTLS_KYBER_KEY key;
memcpy(key.secret_key, my_secret_key, QTLS_KYBER1024_SECRET_KEY_BYTES);
memcpy(key.ciphertext, client_ciphertext, QTLS_KYBER1024_CIPHERTEXT_BYTES);
key.has_secret_key = 1;

int ret = qtls_kyber_decapsulate(&key);
if (ret == QTLS_SUCCESS) {
    // key.shared_secret: 키 유도에 사용
}
```

#### qtls_dilithium_keygen()

```c
int qtls_dilithium_keygen(QTLS_DILITHIUM_KEY *key);
```

**설명**: DILITHIUM3 키쌍을 생성합니다.

**매개변수**:
- `key`: DILITHIUM 키 구조체

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
QTLS_DILITHIUM_KEY key;
memset(&key, 0, sizeof(key));

int ret = qtls_dilithium_keygen(&key);
if (ret == QTLS_SUCCESS) {
    // 공개키 저장
    save_public_key(key.public_key, QTLS_DILITHIUM3_PUBLIC_KEY_BYTES);
    // 비밀키 안전하게 저장 (HSM 권장)
}
```

#### qtls_dilithium_sign()

```c
int qtls_dilithium_sign(const QTLS_DILITHIUM_KEY *key,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t *sig, size_t *sig_len);
```

**설명**: DILITHIUM3로 메시지를 서명합니다.

**매개변수**:
- `key`: 비밀키가 설정된 DILITHIUM 키
- `msg`: 서명할 메시지
- `msg_len`: 메시지 길이
- `sig`: 서명 버퍼
- `sig_len`: 서명 길이 (출력)

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
const char *message = "Sign this message";
uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
size_t sig_len;

int ret = qtls_dilithium_sign(&key,
    (uint8_t *)message, strlen(message),
    signature, &sig_len);

if (ret == QTLS_SUCCESS) {
    printf("Signature length: %zu bytes\n", sig_len);
}
```

#### qtls_dilithium_verify()

```c
int qtls_dilithium_verify(const QTLS_DILITHIUM_KEY *key,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len);
```

**설명**: DILITHIUM3 서명을 검증합니다.

**매개변수**:
- `key`: 공개키가 설정된 DILITHIUM 키
- `msg`: 원본 메시지
- `msg_len`: 메시지 길이
- `sig`: 서명
- `sig_len`: 서명 길이

**반환값**:
- 1: 서명 유효
- 0: 서명 무효
- 음수: 에러

**예제**:
```c
int valid = qtls_dilithium_verify(&key,
    (uint8_t *)message, strlen(message),
    signature, sig_len);

if (valid == 1) {
    printf("Signature is valid\n");
} else if (valid == 0) {
    printf("Signature is invalid\n");
} else {
    printf("Verification error: %s\n",
        qtls_get_error_string(valid));
}
```

### HSM 작업

#### qtls_hsm_init()

```c
int qtls_hsm_init(const char *module_path);
```

**설명**: HSM 연결을 초기화합니다.

**매개변수**:
- `module_path`: PKCS#11 라이브러리 경로

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
int ret = qtls_hsm_init("/usr/lib/libCryptoki2_64.so");
if (ret != QTLS_SUCCESS) {
    fprintf(stderr, "HSM initialization failed\n");
    return 1;
}
```

#### qtls_hsm_login()

```c
int qtls_hsm_login(const char *token_label, const char *pin);
```

**설명**: HSM 토큰에 로그인합니다.

**매개변수**:
- `token_label`: HSM 토큰 레이블
- `pin`: 사용자 PIN

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
int ret = qtls_hsm_login("qtls-server", "my_secure_pin");
if (ret != QTLS_SUCCESS) {
    fprintf(stderr, "HSM login failed\n");
    return 1;
}
```

#### qtls_generate_ephemeral_key_hsm()

```c
int qtls_generate_ephemeral_key_hsm(QTLS_CONNECTION *conn, uint16_t algorithm);
```

**설명**: HSM에서 임시 키를 생성합니다.

**매개변수**:
- `conn`: 연결
- `algorithm`: `QTLS_KEM_KYBER1024` 또는 `QTLS_SIG_DILITHIUM3`

**반환값**: `QTLS_SUCCESS` 또는 에러 코드

**예제**:
```c
// 핸드셰이크 중 KYBER 임시 키 생성
qtls_generate_ephemeral_key_hsm(conn, QTLS_KEM_KYBER1024);
```

#### qtls_hsm_cleanup()

```c
void qtls_hsm_cleanup(void);
```

**설명**: HSM 연결을 정리합니다.

**매개변수**: 없음

**반환값**: 없음

**예제**:
```c
qtls_hsm_cleanup();
```

### 유틸리티

#### qtls_get_error_string()

```c
const char *qtls_get_error_string(int error);
```

**설명**: 에러 코드에 대한 문자열을 반환합니다.

**매개변수**:
- `error`: 에러 코드

**반환값**: 에러 설명 문자열

**예제**:
```c
int ret = qtls_connect(conn);
if (ret != QTLS_SUCCESS) {
    fprintf(stderr, "Error: %s\n", qtls_get_error_string(ret));
}
```

#### qtls_version()

```c
const char *qtls_version(void);
```

**설명**: Q-TLS 라이브러리 버전을 반환합니다.

**매개변수**: 없음

**반환값**: 버전 문자열 (예: "1.0.0")

**예제**:
```c
printf("Q-TLS version: %s\n", qtls_version());
```

#### qtls_get_cipher()

```c
const char *qtls_get_cipher(QTLS_CONNECTION *conn);
```

**설명**: 협상된 암호 스위트를 반환합니다.

**매개변수**:
- `conn`: 연결

**반환값**: 암호 스위트 문자열

**예제**:
```c
const char *cipher = qtls_get_cipher(conn);
printf("Using cipher: %s\n", cipher);
// 출력: "KYBER1024-ECDHE-P384-AES256-GCM-DILITHIUM3-RSA4096"
```

---

## Python 바인딩

### 설치

```bash
pip install qtls
```

### 기본 사용법

```python
import qtls

# 클라이언트 예제
def client_example():
    # 컨텍스트 생성
    ctx = qtls.Context(qtls.CLIENT_MODE)

    # 하이브리드 모드 활성화
    ctx.set_options(qtls.OP_HYBRID_MODE)

    # CA 인증서 로드
    ctx.load_verify_locations("/etc/qtls/certs/ca-bundle.pem")

    # 연결 생성
    conn = qtls.Connection(ctx)

    # 소켓 연결
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("server.example.com", 8443))
    conn.set_socket(sock)

    # SNI 설정
    conn.set_server_name("server.example.com")

    # 핸드셰이크
    conn.connect()

    # 인증서 검증
    if not conn.verify_peer_certificate():
        raise Exception("Certificate verification failed")

    # 데이터 전송
    conn.write(b"Hello Q-TLS!")

    # 데이터 수신
    data = conn.read(4096)
    print(f"Received: {data.decode()}")

    # 연결 종료
    conn.shutdown()
    conn.close()
    sock.close()

# 서버 예제
def server_example():
    # 컨텍스트 생성
    ctx = qtls.Context(qtls.SERVER_MODE)

    # 하이브리드 모드 활성화
    ctx.set_options(qtls.OP_HYBRID_MODE)

    # 인증서 및 키 로드
    ctx.use_certificate_file("/etc/qtls/certs/server-cert.pem",
                              qtls.FILETYPE_PEM)

    # HSM 키 사용
    qtls.hsm_init("/usr/lib/libCryptoki2_64.so")
    qtls.hsm_login("qtls-server", "hsm_pin")
    ctx.use_hsm_key("pkcs11:token=qtls-server;object=server-key")

    # CA 인증서 로드
    ctx.load_verify_locations("/etc/qtls/certs/ca-bundle.pem")

    # 상호 TLS 활성화
    ctx.set_verify_mode(qtls.VERIFY_PEER | qtls.VERIFY_FAIL_IF_NO_PEER_CERT)

    # 리스닝 소켓
    import socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", 8443))
    server_sock.listen(5)

    print("Server listening on port 8443...")

    while True:
        client_sock, addr = server_sock.accept()
        print(f"Connection from {addr}")

        # 연결 생성
        conn = qtls.Connection(ctx)
        conn.set_socket(client_sock)

        try:
            # 핸드셰이크
            conn.accept()

            # 클라이언트 인증서 검증
            if not conn.verify_peer_certificate():
                print("Client certificate verification failed")
                continue

            # 데이터 수신
            data = conn.read(4096)
            print(f"Received: {data.decode()}")

            # 응답 전송
            conn.write(b"Hello from Q-TLS server!")

            # 연결 종료
            conn.shutdown()

        except qtls.QTLSError as e:
            print(f"Error: {e}")
        finally:
            conn.close()
            client_sock.close()

if __name__ == "__main__":
    import sys
    if sys.argv[1] == "client":
        client_example()
    elif sys.argv[1] == "server":
        server_example()
```

### API 레퍼런스

#### Context 클래스

```python
class Context:
    def __init__(self, mode: int)
    def set_options(self, options: int) -> None
    def get_options(self) -> int
    def use_certificate_file(self, file: str, type: int) -> None
    def use_private_key_file(self, file: str, type: int) -> None
    def use_hsm_key(self, uri: str) -> None
    def load_verify_locations(self, file: str = None, path: str = None) -> None
    def set_verify_mode(self, mode: int, callback: Callable = None) -> None
```

#### Connection 클래스

```python
class Connection:
    def __init__(self, ctx: Context)
    def set_socket(self, sock: socket.socket) -> None
    def get_socket(self) -> socket.socket
    def set_server_name(self, hostname: str) -> None
    def connect(self) -> None
    def accept(self) -> None
    def verify_peer_certificate(self) -> bool
    def read(self, num: int) -> bytes
    def write(self, data: bytes) -> int
    def pending(self) -> int
    def shutdown(self) -> None
    def close(self) -> None
    def get_cipher(self) -> str
    def get_peer_certificate(self) -> Certificate
```

---

## Node.js 바인딩

### 설치

```bash
npm install @qsign/qtls
```

### 기본 사용법

```javascript
const qtls = require('@qsign/qtls');

// 클라이언트 예제
async function clientExample() {
    // 컨텍스트 생성
    const ctx = new qtls.Context(qtls.CLIENT_MODE);

    // 하이브리드 모드 활성화
    ctx.setOptions(qtls.OP_HYBRID_MODE);

    // CA 인증서 로드
    ctx.loadVerifyLocations('/etc/qtls/certs/ca-bundle.pem');

    // 연결 생성
    const conn = new qtls.Connection(ctx);

    // 서버 연결
    await conn.connect('server.example.com', 8443);

    // 인증서 검증
    if (!conn.verifyPeerCertificate()) {
        throw new Error('Certificate verification failed');
    }

    // 데이터 전송
    conn.write(Buffer.from('Hello Q-TLS!'));

    // 데이터 수신
    const data = await conn.read();
    console.log(`Received: ${data.toString()}`);

    // 연결 종료
    await conn.shutdown();
    conn.close();
}

// 서버 예제
async function serverExample() {
    // 컨텍스트 생성
    const ctx = new qtls.Context(qtls.SERVER_MODE);

    // 하이브리드 모드 활성화
    ctx.setOptions(qtls.OP_HYBRID_MODE);

    // 인증서 및 키 로드
    ctx.useCertificateFile('/etc/qtls/certs/server-cert.pem',
                            qtls.FILETYPE_PEM);

    // HSM 키 사용
    qtls.hsmInit('/usr/lib/libCryptoki2_64.so');
    qtls.hsmLogin('qtls-server', 'hsm_pin');
    ctx.useHsmKey('pkcs11:token=qtls-server;object=server-key');

    // CA 인증서 로드
    ctx.loadVerifyLocations('/etc/qtls/certs/ca-bundle.pem');

    // 상호 TLS 활성화
    ctx.setVerifyMode(qtls.VERIFY_PEER | qtls.VERIFY_FAIL_IF_NO_PEER_CERT);

    // 서버 시작
    const server = qtls.createServer(ctx, async (conn) => {
        try {
            console.log('Client connected');

            // 클라이언트 인증서 검증
            if (!conn.verifyPeerCertificate()) {
                console.error('Client certificate verification failed');
                return;
            }

            // 데이터 수신
            const data = await conn.read();
            console.log(`Received: ${data.toString()}`);

            // 응답 전송
            conn.write(Buffer.from('Hello from Q-TLS server!'));

            // 연결 종료
            await conn.shutdown();
            conn.close();

        } catch (err) {
            console.error(`Error: ${err.message}`);
        }
    });

    server.listen(8443, () => {
        console.log('Server listening on port 8443...');
    });
}

// 실행
const mode = process.argv[2];
if (mode === 'client') {
    clientExample().catch(console.error);
} else if (mode === 'server') {
    serverExample().catch(console.error);
}
```

---

## Go 바인딩

### 설치

```bash
go get github.com/QSIGN/Q-TLS/bindings/go
```

### 기본 사용법

```go
package main

import (
    "fmt"
    "log"

    "github.com/QSIGN/Q-TLS/bindings/go/qtls"
)

// 클라이언트 예제
func clientExample() error {
    // 컨텍스트 생성
    ctx, err := qtls.NewContext(qtls.ClientMode)
    if err != nil {
        return err
    }
    defer ctx.Free()

    // 하이브리드 모드 활성화
    ctx.SetOptions(qtls.OpHybridMode)

    // CA 인증서 로드
    if err := ctx.LoadVerifyLocations("/etc/qtls/certs/ca-bundle.pem", ""); err != nil {
        return err
    }

    // 연결 생성
    conn, err := qtls.NewConnection(ctx)
    if err != nil {
        return err
    }
    defer conn.Free()

    // SNI 설정
    conn.SetServerName("server.example.com")

    // 서버 연결 및 핸드셰이크
    if err := conn.Connect("server.example.com:8443"); err != nil {
        return err
    }

    // 인증서 검증
    if !conn.VerifyPeerCertificate() {
        return fmt.Errorf("certificate verification failed")
    }

    // 데이터 전송
    if _, err := conn.Write([]byte("Hello Q-TLS!")); err != nil {
        return err
    }

    // 데이터 수신
    buf := make([]byte, 4096)
    n, err := conn.Read(buf)
    if err != nil {
        return err
    }
    fmt.Printf("Received: %s\n", string(buf[:n]))

    // 연결 종료
    conn.Shutdown()

    return nil
}

// 서버 예제
func serverExample() error {
    // 컨텍스트 생성
    ctx, err := qtls.NewContext(qtls.ServerMode)
    if err != nil {
        return err
    }
    defer ctx.Free()

    // 하이브리드 모드 활성화
    ctx.SetOptions(qtls.OpHybridMode)

    // 인증서 및 키 로드
    if err := ctx.UseCertificateFile("/etc/qtls/certs/server-cert.pem",
                                      qtls.FiletypePEM); err != nil {
        return err
    }

    // HSM 초기화
    if err := qtls.HSMInit("/usr/lib/libCryptoki2_64.so"); err != nil {
        return err
    }
    if err := qtls.HSMLogin("qtls-server", "hsm_pin"); err != nil {
        return err
    }

    // HSM 키 사용
    if err := ctx.UseHSMKey("pkcs11:token=qtls-server;object=server-key"); err != nil {
        return err
    }

    // CA 인증서 로드
    if err := ctx.LoadVerifyLocations("/etc/qtls/certs/ca-bundle.pem", ""); err != nil {
        return err
    }

    // 상호 TLS 활성화
    ctx.SetVerifyMode(qtls.VerifyPeer | qtls.VerifyFailIfNoPeerCert, nil)

    // 서버 시작
    listener, err := qtls.Listen("tcp", ":8443", ctx)
    if err != nil {
        return err
    }
    defer listener.Close()

    log.Println("Server listening on port 8443...")

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Accept error: %v", err)
            continue
        }

        go handleClient(conn)
    }
}

func handleClient(conn *qtls.Connection) {
    defer conn.Free()
    defer conn.Close()

    log.Println("Client connected")

    // 클라이언트 인증서 검증
    if !conn.VerifyPeerCertificate() {
        log.Println("Client certificate verification failed")
        return
    }

    // 데이터 수신
    buf := make([]byte, 4096)
    n, err := conn.Read(buf)
    if err != nil {
        log.Printf("Read error: %v", err)
        return
    }
    log.Printf("Received: %s", string(buf[:n]))

    // 응답 전송
    if _, err := conn.Write([]byte("Hello from Q-TLS server!")); err != nil {
        log.Printf("Write error: %v", err)
        return
    }

    // 연결 종료
    conn.Shutdown()
}

func main() {
    mode := os.Args[1]

    var err error
    if mode == "client" {
        err = clientExample()
    } else if mode == "server" {
        err = serverExample()
    } else {
        log.Fatal("Usage: program [client|server]")
    }

    if err != nil {
        log.Fatal(err)
    }
}
```

---

## 에러 코드

### 일반 에러

| 코드 | 값 | 설명 |
|------|-----|------|
| `QTLS_SUCCESS` | 0 | 성공 |
| `QTLS_ERROR_GENERIC` | -1 | 일반 에러 |
| `QTLS_ERROR_NULL_POINTER` | -2 | NULL 포인터 |
| `QTLS_ERROR_INVALID_ARGUMENT` | -3 | 잘못된 인자 |
| `QTLS_ERROR_OUT_OF_MEMORY` | -4 | 메모리 부족 |
| `QTLS_ERROR_SYSCALL` | -5 | 시스템 호출 실패 |
| `QTLS_ERROR_WANT_READ` | -6 | 읽기 대기 필요 |
| `QTLS_ERROR_WANT_WRITE` | -7 | 쓰기 대기 필요 |
| `QTLS_ERROR_ZERO_RETURN` | -8 | 연결 종료 |

### 암호화 에러

| 코드 | 값 | 설명 |
|------|-----|------|
| `QTLS_ERROR_CRYPTO_INIT` | -100 | 암호화 초기화 실패 |
| `QTLS_ERROR_KEY_GENERATION` | -101 | 키 생성 실패 |
| `QTLS_ERROR_ENCAPSULATION` | -102 | 캡슐화 실패 |
| `QTLS_ERROR_DECAPSULATION` | -103 | 역캡슐화 실패 |
| `QTLS_ERROR_SIGNATURE` | -104 | 서명 실패 |
| `QTLS_ERROR_VERIFICATION` | -105 | 검증 실패 |
| `QTLS_ERROR_KEY_DERIVATION` | -106 | 키 유도 실패 |
| `QTLS_ERROR_ENCRYPTION` | -107 | 암호화 실패 |
| `QTLS_ERROR_DECRYPTION` | -108 | 복호화 실패 |

### 프로토콜 에러

| 코드 | 값 | 설명 |
|------|-----|------|
| `QTLS_ERROR_HANDSHAKE_FAILED` | -200 | 핸드셰이크 실패 |
| `QTLS_ERROR_PROTOCOL_VERSION` | -201 | 프로토콜 버전 불일치 |
| `QTLS_ERROR_CERT_VERIFY_FAILED` | -202 | 인증서 검증 실패 |
| `QTLS_ERROR_PEER_CLOSED` | -203 | 피어 연결 종료 |
| `QTLS_ERROR_INVALID_MESSAGE` | -204 | 잘못된 메시지 |
| `QTLS_ERROR_UNSUPPORTED_ALGO` | -205 | 지원되지 않는 알고리즘 |

### HSM 에러

| 코드 | 값 | 설명 |
|------|-----|------|
| `QTLS_ERROR_HSM_NOT_AVAILABLE` | -300 | HSM 사용 불가 |
| `QTLS_ERROR_HSM_INIT_FAILED` | -301 | HSM 초기화 실패 |
| `QTLS_ERROR_HSM_LOGIN_FAILED` | -302 | HSM 로그인 실패 |
| `QTLS_ERROR_HSM_KEY_NOT_FOUND` | -303 | HSM 키를 찾을 수 없음 |
| `QTLS_ERROR_HSM_OPERATION_FAILED` | -304 | HSM 작업 실패 |

---

**문서 버전**: 1.0.0
**최종 업데이트**: 2025년 1월 16일
**작성자**: QSIGN Project Team
