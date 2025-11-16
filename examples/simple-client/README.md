# Q-TLS Simple Client Example

간단한 Q-TLS 클라이언트 구현 예제

## 개요

이 예제는 Q-TLS 라이브러리를 사용하여 양자 내성(Post-Quantum) 암호화를 지원하는 기본적인 TLS 클라이언트를 구현하는 방법을 보여줍니다.

## 주요 특징

- **하이브리드 암호화**: 기존 ECDHE P-384와 양자 내성 Kyber1024를 결합
- **양자 내성 서명**: Dilithium3 디지털 서명 검증
- **유연한 인증서 검증**: 테스트 환경과 프로덕션 환경 모드 지원
- **SNI 지원**: Server Name Indication 자동 설정

## 빌드 방법

### 사전 요구사항

```bash
# Q-TLS 라이브러리 빌드 필요
cd ../../
mkdir build && cd build
cmake .. -DENABLE_EXAMPLES=ON
make
cd ../examples/simple-client
```

### 클라이언트 빌드

```bash
# Makefile을 사용한 빌드
make

# 또는 직접 컴파일
gcc -o simple_client simple_client.c \
    -I../../include \
    -L../../build \
    -lqtls -loqs -lssl -lcrypto -lpthread -lm
```

## 실행 방법

### 기본 사용법

```bash
./simple_client [호스트] [포트] [메시지] [-verify]
```

**매개변수:**
- `호스트`: 서버 호스트명 또는 IP (기본값: localhost)
- `포트`: 서버 포트 번호 (기본값: 8443)
- `메시지`: 전송할 메시지 (기본값: "안녕하세요! Q-TLS 클라이언트입니다.")
- `-verify`: 서버 인증서 검증 활성화 (선택적)

### 실행 예시

#### localhost 서버 테스트

```bash
# Makefile을 사용한 실행
make run

# 또는 직접 실행
LD_LIBRARY_PATH=../../build:$LD_LIBRARY_PATH ./simple_client localhost 8443
```

#### 사용자 지정 서버 테스트

```bash
# 원격 서버 연결
./simple_client example.com 8443

# 사용자 지정 메시지
./simple_client localhost 9443 "Hello, Q-TLS!"

# 인증서 검증 활성화
./simple_client example.com 8443 "Hello" -verify
```

#### Makefile을 사용한 원격 테스트

```bash
make test HOST=example.com PORT=8443
```

### 클라이언트 출력 예시

```
===========================================
  Q-TLS Simple Client Example
  양자 내성 TLS 클라이언트 예제
===========================================
Q-TLS 버전: 1.0.0

연결 정보:
  호스트: localhost
  포트: 8443
  메시지: 안녕하세요! Q-TLS 클라이언트입니다.
  인증서 검증: 비활성화

[INFO] Q-TLS 클라이언트 컨텍스트 초기화 중...
[INFO] 하이브리드 모드 활성화 (ECDHE + Kyber1024)
[WARN] 인증서 검증 비활성화 (테스트 모드)
[INFO] PQC 알고리즘: Kyber1024 (KEM), Dilithium3 (Signature)
[INFO] 연결 대상: localhost (127.0.0.1:8443)
[INFO] 서버에 연결 중...
[SUCCESS] TCP 연결 성공
[INFO] SNI 설정: localhost

[INFO] Q-TLS 핸드셰이크 시작...
[SUCCESS] Q-TLS 핸드셰이크 완료!
[INFO] 사용 암호 스위트: TLS_AES_256_GCM_SHA384_KYBER1024_DILITHIUM3
[INFO] 프로토콜 버전: 0x0304

[INFO] 메시지 전송 중...
[SEND] 안녕하세요! Q-TLS 클라이언트입니다.
[SUCCESS] 전송 완료: 51 바이트

[INFO] 서버 응답 대기 중...
[RECEIVED] 서버 응답: 안녕하세요! Q-TLS 서버입니다. 메시지를 정상적으로 수신했습니다.
[SUCCESS] 수신 완료: 99 바이트

[INFO] 연결 종료 중...

[SUCCESS] 통신 완료!
```

## 코드 구조

### main() 함수 흐름

1. **초기화**
   - 명령행 인자 파싱
   - 버전 정보 출력

2. **통신 수행**
   - `qtls_communicate()` 호출

### qtls_communicate() 함수

1. **컨텍스트 설정**
   - Q-TLS 클라이언트 컨텍스트 생성
   - 하이브리드 모드 활성화
   - 인증서 검증 모드 설정
   - PQC 알고리즘 설정

2. **연결 설정**
   - TCP 소켓 생성 및 연결
   - Q-TLS 연결 객체 생성
   - SNI 설정

3. **핸드셰이크**
   - `qtls_connect()` 호출
   - 협상된 정보 확인

4. **데이터 교환**
   - 메시지 전송 (`qtls_write()`)
   - 응답 수신 (`qtls_read()`)

5. **종료**
   - 연결 종료 (`qtls_shutdown()`)
   - 리소스 정리

### connect_to_server() 함수

- 호스트명을 IP로 변환
- TCP 소켓 생성
- 서버 연결

## 인증서 검증

### 테스트 모드 (기본값)

```bash
# 인증서 검증 비활성화 - 자체 서명 인증서 허용
./simple_client localhost 8443
```

이 모드는 다음 환경에 적합합니다:
- 로컬 테스트
- 자체 서명 인증서 사용
- 개발 환경

### 프로덕션 모드

```bash
# 인증서 검증 활성화
./simple_client example.com 8443 "Hello" -verify
```

이 모드는 다음을 확인합니다:
- 서버 인증서의 유효성
- 인증서 체인 검증
- 인증서 만료일
- 호스트명 일치 여부

### CA 인증서 설정 (프로덕션)

프로덕션 환경에서는 CA 인증서를 로드해야 합니다:

```c
// 코드 수정 예시
qtls_ctx_load_verify_locations(ctx, "/etc/ssl/certs/ca-bundle.crt", NULL);
qtls_ctx_set_verify_mode(ctx, QTLS_VERIFY_PEER, NULL);
```

## 고급 사용 예시

### 1. 여러 메시지 전송

```c
// qtls_communicate() 함수 내에서 반복 전송
for (int i = 0; i < 10; i++) {
    char msg[256];
    snprintf(msg, sizeof(msg), "메시지 #%d", i);
    qtls_write(conn, msg, strlen(msg));

    qtls_read(conn, buffer, sizeof(buffer));
    printf("응답: %s\n", buffer);
}
```

### 2. 파일 전송

```c
// 파일 읽기 및 전송
FILE *fp = fopen("data.txt", "rb");
char chunk[4096];
size_t bytes;

while ((bytes = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
    qtls_write(conn, chunk, bytes);
}
fclose(fp);
```

### 3. 클라이언트 인증서 사용

```c
// 상호 TLS 인증 설정
qtls_ctx_use_certificate_file(ctx, "client.crt", QTLS_FILETYPE_PEM);
qtls_ctx_use_private_key_file(ctx, "client.key", QTLS_FILETYPE_PEM);
```

## 서버와 함께 테스트

### 1. 서버 시작

```bash
cd ../simple-server
make
make run
```

### 2. 클라이언트 실행

```bash
cd ../simple-client
make run
```

### 3. 동시 실행 스크립트

```bash
#!/bin/bash
# test_qtls.sh

# 서버 백그라운드 실행
cd ../simple-server
./simple_server &
SERVER_PID=$!

# 서버 시작 대기
sleep 2

# 클라이언트 실행
cd ../simple-client
./simple_client localhost 8443

# 서버 종료
kill $SERVER_PID
```

## 문제 해결

### 연결 실패

```
connect() 실패: Connection refused
```

**해결책**:
- 서버가 실행 중인지 확인
- 포트 번호가 올바른지 확인
- 방화벽 설정 확인

### 핸드셰이크 실패

```
[ERROR] qtls_connect() 실패
```

**가능한 원인**:
- 서버와 클라이언트의 PQC 알고리즘 불일치
- 네트워크 타임아웃
- 인증서 문제

**해결책**:
```bash
# 서버 로그 확인
# 양측의 알고리즘 설정 확인
# 네트워크 연결 확인
```

### 라이브러리 로드 오류

```
error while loading shared libraries: libqtls.so
```

**해결책**:
```bash
export LD_LIBRARY_PATH=../../build:$LD_LIBRARY_PATH
./simple_client localhost 8443
```

## 성능 고려사항

### PQC 핸드셰이크 성능

- **Kyber1024 키 교환**: ~0.1ms
- **Dilithium3 서명 검증**: ~0.5ms
- **전체 핸드셰이크**: ~5-10ms (네트워크 지연 포함)

### 최적화 팁

1. **연결 재사용**: 여러 메시지 전송 시 연결 재사용
2. **세션 재개**: TLS 세션 캐싱 활용
3. **버퍼 크기 조정**: 대용량 데이터 전송 시 버퍼 크기 증가

## 다음 단계

이 예제를 이해했다면 다음을 학습하세요:

1. **Mutual TLS** (`../mutual-tls`): 클라이언트 인증서 기반 상호 인증
2. **QSIGN Integration** (`../qsign-integration`): QSIGN PKI 및 HSM 통합
3. **Advanced Features**: 세션 재개, 연결 풀링, 에러 복구

## 참고 자료

- [Q-TLS API 문서](../../docs/API.md)
- [Simple Server 예제](../simple-server/README.md)
- [Mutual TLS 예제](../mutual-tls/README.md)
- [QSIGN 통합 가이드](../qsign-integration/README.md)

## 라이선스

Apache License 2.0 - 자세한 내용은 프로젝트 루트의 LICENSE 파일 참조
