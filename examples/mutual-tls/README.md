# Q-TLS Mutual TLS Example

상호 TLS 인증(mTLS) 구현 예제

## 개요

이 예제는 Q-TLS 라이브러리를 사용하여 **상호 TLS 인증**(Mutual TLS, mTLS)을 구현하는 방법을 보여줍니다. 상호 TLS에서는 서버뿐만 아니라 클라이언트도 인증서를 제공하여 양방향 인증을 수행합니다.

## 상호 TLS란?

일반적인 TLS 연결에서는 서버만 인증서를 제공하여 신원을 증명합니다. 하지만 **상호 TLS(mTLS)**에서는:

- **서버**: 자신의 인증서를 클라이언트에게 제공
- **클라이언트**: 자신의 인증서를 서버에게 제공
- **양방향 인증**: 서버와 클라이언트 모두 상대방의 신원을 확인

### 사용 사례

- **마이크로서비스 간 통신**: 서비스 간 상호 인증
- **API 보안**: 인증된 클라이언트만 API 접근 허용
- **IoT 디바이스**: 디바이스와 서버 간 상호 인증
- **제로 트러스트 아키텍처**: 모든 연결에 대한 인증 요구
- **금융 시스템**: 높은 보안이 필요한 거래

## 주요 특징

- **양방향 인증**: 서버와 클라이언트 모두 인증서 검증
- **CA 기반 신뢰**: 자체 CA를 사용한 인증서 체인 검증
- **하이브리드 PQC**: 양자 내성 암호화 적용
- **세밀한 접근 제어**: 인증서 기반 클라이언트 식별

## 디렉토리 구조

```
mutual-tls/
├── mtls_server.c          # 상호 TLS 서버 구현
├── mtls_client.c          # 상호 TLS 클라이언트 구현
├── Makefile               # 빌드 파일
├── generate_certs.sh      # 인증서 생성 스크립트
├── README.md              # 이 파일
└── certs/                 # 생성된 인증서 디렉토리 (자동 생성)
    ├── ca.crt             # CA 인증서
    ├── ca.key             # CA 개인키
    ├── server.crt         # 서버 인증서
    ├── server.key         # 서버 개인키
    ├── client.crt         # 클라이언트 인증서
    └── client.key         # 클라이언트 개인키
```

## 빌드 및 실행

### 1. 사전 요구사항

```bash
# Q-TLS 라이브러리 빌드
cd ../../
mkdir build && cd build
cmake .. -DENABLE_EXAMPLES=ON
make
cd ../examples/mutual-tls
```

### 2. 인증서 생성

상호 TLS를 위해서는 CA, 서버, 클라이언트 인증서가 필요합니다:

```bash
# 인증서 자동 생성
make certs

# 또는 직접 실행
bash generate_certs.sh
```

생성되는 인증서:
- **CA 인증서** (`ca.crt`): 서버와 클라이언트 인증서를 서명하는 루트 CA
- **서버 인증서** (`server.crt`): CA로 서명된 서버 인증서
- **클라이언트 인증서** (`client.crt`): CA로 서명된 클라이언트 인증서

### 3. 인증서 검증

생성된 인증서 정보 확인:

```bash
make verify-certs
```

출력 예시:
```
========== CA 인증서 정보 ==========
Subject: C=KR, ST=Seoul, L=Seoul, O=QSIGN Project, OU=Certificate Authority, CN=QSIGN Root CA
Issuer: C=KR, ST=Seoul, L=Seoul, O=QSIGN Project, OU=Certificate Authority, CN=QSIGN Root CA
Not Before: Nov 16 12:00:00 2025 GMT
Not After : Nov 16 12:00:00 2026 GMT

========== 서버 인증서 정보 ==========
Subject: C=KR, ST=Seoul, L=Seoul, O=QSIGN Project, OU=Q-TLS Server, CN=localhost
Issuer: C=KR, ST=Seoul, L=Seoul, O=QSIGN Project, OU=Certificate Authority, CN=QSIGN Root CA
Not Before: Nov 16 12:00:00 2025 GMT
Not After : Nov 16 12:00:00 2026 GMT

========== 클라이언트 인증서 정보 ==========
Subject: C=KR, ST=Seoul, L=Seoul, O=QSIGN Project, OU=Q-TLS Client, CN=QSIGN Client
Issuer: C=KR, ST=Seoul, L=Seoul, O=QSIGN Project, OU=Certificate Authority, CN=QSIGN Root CA
Not Before: Nov 16 12:00:00 2025 GMT
Not After : Nov 16 12:00:00 2026 GMT
```

### 4. 서버와 클라이언트 빌드

```bash
# 서버와 클라이언트 모두 빌드
make
```

### 5. 실행

#### 터미널 1: 서버 시작

```bash
make run-server

# 또는
LD_LIBRARY_PATH=../../build:$LD_LIBRARY_PATH ./mtls_server
```

서버 출력:
```
===============================================
  Q-TLS Mutual TLS Server Example
  양자 내성 상호 TLS 인증 서버 예제
===============================================
Q-TLS 버전: 1.0.0

[INFO] Q-TLS 서버 컨텍스트 초기화 중...
[INFO] 하이브리드 모드 활성화 (ECDHE + Kyber1024)
[INFO] 클라이언트 인증서 검증 활성화 (상호 인증 모드)
[INFO] CA 인증서 로드: certs/ca.crt
[INFO] 서버 인증서 로드: certs/server.crt
[INFO] 서버 개인키 로드: certs/server.key
[INFO] PQC 알고리즘: Kyber1024 (KEM), Dilithium3 (Signature)
[INFO] 서버 소켓 생성 완료: 포트 8443

[SUCCESS] Q-TLS 상호 인증 서버 시작!
[INFO] 포트 8443에서 클라이언트 연결 대기 중...
[INFO] 클라이언트 인증서가 필수입니다.
[INFO] 종료하려면 Ctrl+C를 누르세요.
```

#### 터미널 2: 클라이언트 실행

```bash
make run-client

# 또는
LD_LIBRARY_PATH=../../build:$LD_LIBRARY_PATH ./mtls_client
```

클라이언트 출력:
```
===================================================
  Q-TLS Mutual TLS Client Example
  양자 내성 상호 TLS 인증 클라이언트 예제
===================================================
Q-TLS 버전: 1.0.0

연결 정보:
  호스트: localhost
  포트: 8443
  메시지: 안녕하세요! 인증된 Q-TLS 클라이언트입니다.
  인증 모드: 상호 TLS (클라이언트 인증서 사용)

[INFO] Q-TLS 클라이언트 컨텍스트 초기화 중...
[INFO] 하이브리드 모드 활성화 (ECDHE + Kyber1024)
[INFO] 클라이언트 인증서 로드: certs/client.crt
[INFO] 클라이언트 개인키 로드: certs/client.key
[INFO] CA 인증서 로드: certs/ca.crt
[INFO] 서버 인증서 검증 활성화
[INFO] PQC 알고리즘: Kyber1024 (KEM), Dilithium3 (Signature)
[INFO] 연결 대상: localhost (127.0.0.1:8443)
[INFO] 서버에 연결 중...
[SUCCESS] TCP 연결 성공
[INFO] SNI 설정: localhost

[INFO] Q-TLS 상호 인증 핸드셰이크 시작...
[INFO] 클라이언트 인증서 제공 중...
[SUCCESS] 상호 인증 핸드셰이크 완료!
[INFO] 사용 암호 스위트: TLS_AES_256_GCM_SHA384_KYBER1024_DILITHIUM3
[INFO] 프로토콜 버전: 0x0304
[SUCCESS] 서버 인증서 검증 성공!
[INFO] 서버 인증서 수신 완료 (1234 바이트)

[INFO] 인증 완료, 메시지 전송 중...
[SEND] 안녕하세요! 인증된 Q-TLS 클라이언트입니다.
[SUCCESS] 전송 완료: 63 바이트

[INFO] 서버 응답 대기 중...
[RECEIVED] 서버 응답: 인증 성공! Q-TLS 상호 인증 서버입니다. 클라이언트 인증서가 확인되었습니다.
[SUCCESS] 수신 완료: 117 바이트

[INFO] 연결 종료 중...

[SUCCESS] 상호 인증 통신 완료!
[INFO] 클라이언트와 서버 모두 인증되었습니다.
```

## 코드 분석

### 서버 코드 (mtls_server.c)

#### 1. 클라이언트 인증서 검증 설정

```c
// 클라이언트 인증서 요구 및 검증 실패 시 연결 거부
qtls_ctx_set_verify_mode(ctx,
    QTLS_VERIFY_PEER | QTLS_VERIFY_FAIL_IF_NO_PEER_CERT,
    verify_client_callback);

// CA 인증서 로드 - 클라이언트 인증서 검증에 사용
qtls_ctx_load_verify_locations(ctx, "certs/ca.crt", NULL);
```

#### 2. 검증 콜백 함수

```c
int verify_client_callback(int preverify_ok, QTLS_X509 *x509_ctx) {
    if (!preverify_ok) {
        // 인증서 검증 실패 시 처리
        // 프로덕션: return 0; (연결 거부)
        // 테스트: return 1; (허용)
    }
    return 1;
}
```

#### 3. 클라이언트 인증서 정보 확인

```c
// 핸드셰이크 후 클라이언트 인증서 검증
int ret = qtls_verify_peer_certificate(conn);
if (ret == 1) {
    // 인증 성공
    QTLS_CERTIFICATE *cert = qtls_get_peer_certificate(conn);
    // 인증서 정보 확인 및 처리
    qtls_certificate_free(cert);
}
```

### 클라이언트 코드 (mtls_client.c)

#### 1. 클라이언트 인증서 로드

```c
// 클라이언트 인증서 및 개인키 로드
qtls_ctx_use_certificate_file(ctx, "certs/client.crt", QTLS_FILETYPE_PEM);
qtls_ctx_use_private_key_file(ctx, "certs/client.key", QTLS_FILETYPE_PEM);
```

#### 2. 서버 인증서 검증 설정

```c
// CA 인증서 로드
qtls_ctx_load_verify_locations(ctx, "certs/ca.crt", NULL);

// 서버 인증서 검증 활성화
qtls_ctx_set_verify_mode(ctx, QTLS_VERIFY_PEER, verify_server_callback);
```

## 인증서 관리

### 인증서 체인

```
CA (ca.crt)
├── 서버 인증서 (server.crt)
│   └── 서명: CA
└── 클라이언트 인증서 (client.crt)
    └── 서명: CA
```

### 검증 프로세스

1. **서버 측 검증**:
   - 클라이언트가 제공한 인증서 수신
   - CA 인증서로 클라이언트 인증서 서명 검증
   - 인증서 유효 기간 확인
   - 인증서 폐기 목록(CRL) 확인 (선택적)

2. **클라이언트 측 검증**:
   - 서버가 제공한 인증서 수신
   - CA 인증서로 서버 인증서 서명 검증
   - 호스트명 일치 확인 (SNI)
   - 인증서 유효 기간 확인

### 인증서 갱신

```bash
# 기존 인증서 삭제
make distclean

# 새 인증서 생성
make certs
```

## 고급 사용 예시

### 1. 여러 클라이언트 인증서 허용

서버에서 여러 CA의 인증서를 신뢰:

```c
// 여러 CA 인증서 로드
qtls_ctx_load_verify_locations(ctx, "certs/ca-bundle.crt", NULL);

// 또는 디렉토리 경로 지정
qtls_ctx_load_verify_locations(ctx, NULL, "certs/trusted_cas/");
```

### 2. 클라이언트 구분 및 접근 제어

검증 콜백에서 클라이언트 인증서 정보 추출:

```c
int verify_client_callback(int preverify_ok, QTLS_X509 *x509_ctx) {
    if (!preverify_ok) {
        return 0;  // 검증 실패 시 거부
    }

    // 인증서에서 CN (Common Name) 추출
    // 클라이언트 별 접근 권한 확인
    // 예: "CN=admin-client" -> 관리자 권한
    //     "CN=user-client" -> 일반 사용자 권한

    return 1;
}
```

### 3. 인증서 폐기 목록(CRL) 확인

```c
// CRL 파일 로드 및 검증 (구현 예정)
// qtls_ctx_load_crl(ctx, "certs/revoked.crl");
```

## 프로덕션 고려사항

### 1. 인증서 관리

- **프로덕션 CA 사용**: Let's Encrypt, DigiCert 등 신뢰할 수 있는 CA
- **인증서 자동화**: certbot, cert-manager 등 자동 갱신 도구
- **HSM 통합**: 개인키를 HSM에 저장

```c
// HSM에서 서버 개인키 사용
qtls_hsm_init("/usr/lib/libCryptoki2_64.so");
qtls_hsm_login("luna-token", "user-pin");
qtls_ctx_use_hsm_key(ctx, "pkcs11:token=luna;object=server-key");
```

### 2. 보안 강화

```c
// 강력한 검증 모드
qtls_ctx_set_verify_mode(ctx,
    QTLS_VERIFY_PEER |
    QTLS_VERIFY_FAIL_IF_NO_PEER_CERT |
    QTLS_VERIFY_CLIENT_ONCE,
    strict_verify_callback);

// CRL 및 OCSP 검증 활성화
// qtls_ctx_enable_crl_check(ctx);
// qtls_ctx_enable_ocsp(ctx);
```

### 3. 성능 최적화

- **인증서 캐싱**: 검증된 인증서 정보 캐싱
- **세션 재개**: TLS 세션 티켓 사용
- **연결 풀링**: 연결 재사용

## 문제 해결

### 인증서 검증 실패

```
[ERROR] qtls_accept() 실패: 클라이언트 인증서 검증 실패
```

**원인**:
- 클라이언트 인증서가 CA로 서명되지 않음
- CA 인증서가 올바르게 로드되지 않음
- 인증서가 만료됨

**해결**:
```bash
# 인증서 재생성
make distclean
make certs

# 인증서 검증
make verify-certs
```

### 클라이언트 인증서 없음

```
[ERROR] 클라이언트 인증서가 제공되지 않음
```

**원인**:
- 클라이언트가 인증서를 로드하지 않음

**해결**:
```c
// 클라이언트 코드 확인
qtls_ctx_use_certificate_file(ctx, "certs/client.crt", QTLS_FILETYPE_PEM);
qtls_ctx_use_private_key_file(ctx, "certs/client.key", QTLS_FILETYPE_PEM);
```

## 다음 단계

이 예제를 이해했다면 다음을 학습하세요:

1. **QSIGN Integration** (`../qsign-integration`): QSIGN PKI 시스템과 통합
2. **HSM 통합**: Luna HSM을 사용한 키 관리
3. **고급 인증**: OCSP, CRL, 인증서 투명성 로그

## 참고 자료

- [Q-TLS API 문서](../../docs/API.md)
- [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
- [X.509 인증서 표준](https://tools.ietf.org/html/rfc5280)
- [mTLS 보안 가이드](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)

## 라이선스

Apache License 2.0 - 자세한 내용은 프로젝트 루트의 LICENSE 파일 참조
