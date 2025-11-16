# Q-TLS Simple Server Example

간단한 Q-TLS 서버 구현 예제

## 개요

이 예제는 Q-TLS 라이브러리를 사용하여 양자 내성(Post-Quantum) 암호화를 지원하는 기본적인 TLS 서버를 구현하는 방법을 보여줍니다.

## 주요 특징

- **하이브리드 암호화**: 기존 ECDHE P-384와 양자 내성 Kyber1024를 결합
- **양자 내성 서명**: Dilithium3 디지털 서명 알고리즘 사용
- **간단한 구조**: 기본적인 서버 구현으로 학습에 최적
- **에러 처리**: 적절한 에러 처리 및 로깅 포함

## 사용된 암호 알고리즘

### 키 교환 (KEM)
- **Kyber1024** (ML-KEM-1024): NIST 표준화된 양자 내성 KEM
- **ECDHE P-384**: 기존 타원곡선 키 교환
- **하이브리드 모드**: 두 알고리즘을 결합하여 최대 보안성 확보

### 디지털 서명
- **Dilithium3** (ML-DSA-65): NIST 표준화된 양자 내성 서명
- **RSA-4096** 또는 **ECDSA P-384**: 기존 서명 알고리즘과 하이브리드 지원

### 대칭 암호화
- **AES-256-GCM**: 데이터 암호화 및 인증

## 빌드 방법

### 사전 요구사항

```bash
# Q-TLS 라이브러리 빌드 필요
cd ../../
mkdir build && cd build
cmake .. -DENABLE_EXAMPLES=ON
make
cd ../examples/simple-server
```

### 인증서 생성

```bash
# 자체 서명 테스트 인증서 생성
bash generate_certs.sh
```

생성되는 파일:
- `server.crt`: 서버 인증서 (RSA 4096-bit)
- `server.key`: 서버 개인키
- `server.csr`: 인증서 서명 요청

### 서버 빌드

```bash
# Makefile을 사용한 빌드
make

# 또는 직접 컴파일
gcc -o simple_server simple_server.c \
    -I../../include \
    -L../../build \
    -lqtls -loqs -lssl -lcrypto -lpthread -lm
```

## 실행 방법

### 기본 실행 (포트 8443)

```bash
make run

# 또는
LD_LIBRARY_PATH=../../build:$LD_LIBRARY_PATH ./simple_server
```

### 사용자 지정 포트로 실행

```bash
./simple_server 9443

# 사용자 지정 인증서 사용
./simple_server 9443 /path/to/cert.pem /path/to/key.pem
```

### 서버 출력 예시

```
===========================================
  Q-TLS Simple Server Example
  양자 내성 TLS 서버 예제
===========================================
Q-TLS 버전: 1.0.0

[INFO] Q-TLS 서버 컨텍스트 초기화 중...
[INFO] 하이브리드 모드 활성화 (ECDHE + Kyber1024)
[INFO] 서버 인증서 로드: server.crt
[INFO] 서버 개인키 로드: server.key
[INFO] PQC 알고리즘: Kyber1024 (KEM), Dilithium3 (Signature)
[INFO] 서버 소켓 생성 완료: 포트 8443

[SUCCESS] Q-TLS 서버 시작!
[INFO] 포트 8443에서 클라이언트 연결 대기 중...
[INFO] 종료하려면 Ctrl+C를 누르세요.
```

## 클라이언트 테스트

간단한 테스트 클라이언트 사용:

```bash
# simple-client 예제 사용
cd ../simple-client
make
./simple_client localhost 8443
```

OpenSSL s_client를 사용한 테스트 (기존 TLS 호환성 확인):

```bash
openssl s_client -connect localhost:8443 -CAfile server.crt
```

## 코드 구조

### main() 함수 흐름

1. **초기화**
   - 명령행 인자 파싱
   - 시그널 핸들러 등록
   - Q-TLS 컨텍스트 생성

2. **설정**
   - 하이브리드 모드 활성화
   - 서버 인증서 및 개인키 로드
   - PQC 알고리즘 설정

3. **서버 시작**
   - TCP 소켓 생성 및 바인딩
   - 연결 대기 시작

4. **메인 루프**
   - 클라이언트 연결 수락
   - 각 클라이언트 처리
   - 시그널 확인

### handle_client() 함수

각 클라이언트 연결에 대해:

1. Q-TLS 연결 객체 생성
2. 소켓 연결
3. TLS 핸드셰이크 수행 (`qtls_accept()`)
4. 데이터 수신 (`qtls_read()`)
5. 응답 전송 (`qtls_write()`)
6. 연결 종료

## 보안 고려사항

### 테스트 환경

- 자체 서명 인증서 사용 가능
- localhost에서만 접근 허용
- 간단한 에러 처리

### 프로덕션 환경

이 예제를 프로덕션에 사용하려면 다음을 추가해야 합니다:

1. **신뢰할 수 있는 인증서**
   ```c
   // CA에서 발급받은 인증서 사용
   qtls_ctx_use_certificate_file(ctx, "/etc/ssl/certs/server.crt", QTLS_FILETYPE_PEM);
   qtls_ctx_use_private_key_file(ctx, "/etc/ssl/private/server.key", QTLS_FILETYPE_PEM);
   ```

2. **클라이언트 인증서 검증**
   ```c
   // 클라이언트 인증서 요구
   qtls_ctx_set_verify_mode(ctx,
       QTLS_VERIFY_PEER | QTLS_VERIFY_FAIL_IF_NO_PEER_CERT,
       NULL);
   qtls_ctx_load_verify_locations(ctx, "/etc/ssl/certs/ca-bundle.crt", NULL);
   ```

3. **HSM 통합** (Luna HSM 사용 시)
   ```c
   // HSM에서 개인키 사용
   qtls_hsm_init("/usr/lib/libCryptoki2_64.so");
   qtls_hsm_login("luna-token", "user-pin");
   qtls_ctx_use_hsm_key(ctx, "pkcs11:token=luna-token;object=server-key");
   ```

4. **멀티 스레드 처리**
   - 각 클라이언트를 별도 스레드에서 처리
   - 연결 풀 관리
   - 리소스 제한 설정

5. **로깅 및 모니터링**
   - 상세한 보안 이벤트 로깅
   - 성능 메트릭 수집
   - 비정상 패턴 탐지

## 문제 해결

### 인증서 오류

```
[ERROR] 인증서 로드 실패
```

**해결책**: 인증서 파일 생성
```bash
bash generate_certs.sh
```

### 포트 바인딩 오류

```
bind() 실패: Address already in use
```

**해결책**:
- 다른 포트 사용: `./simple_server 9443`
- 기존 프로세스 종료: `lsof -ti:8443 | xargs kill`

### 라이브러리 로드 오류

```
error while loading shared libraries: libqtls.so
```

**해결책**:
```bash
export LD_LIBRARY_PATH=../../build:$LD_LIBRARY_PATH
./simple_server
```

## 다음 단계

이 예제를 이해했다면 다음을 학습하세요:

1. **Simple Client** (`../simple-client`): Q-TLS 클라이언트 구현
2. **Mutual TLS** (`../mutual-tls`): 상호 TLS 인증
3. **QSIGN Integration** (`../qsign-integration`): QSIGN PKI 및 HSM 통합

## 참고 자료

- [Q-TLS API 문서](../../docs/API.md)
- [Kyber 알고리즘 스펙](https://pq-crystals.org/kyber/)
- [Dilithium 알고리즘 스펙](https://pq-crystals.org/dilithium/)
- [NIST PQC 표준화](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 라이선스

Apache License 2.0 - 자세한 내용은 프로젝트 루트의 LICENSE 파일 참조
