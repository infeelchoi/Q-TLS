# Q-TLS 인증서 생성 도구

양자 내성 알고리즘(Dilithium)을 사용한 X.509 인증서 생성 유틸리티입니다.

## 빌드

```bash
make
```

## 사용법

### 1. CA 인증서 생성

```bash
# 스크립트 사용 (권장)
./generate-ca.sh ./certs

# 또는 certgen 직접 사용
./certgen -t ca \
  -s "/C=KR/O=MyOrg/CN=My Root CA" \
  -o ca-cert.pem \
  -k ca-key.pem \
  -d 3650
```

### 2. 서버 인증서 생성

```bash
# 스크립트 사용
./generate-server.sh ./certs server.example.com

# 또는 certgen 직접 사용
./certgen -t server \
  -s "/C=KR/O=MyOrg/CN=server.example.com" \
  -c ca-cert.pem \
  -K ca-key.pem \
  -o server-cert.pem \
  -k server-key.pem \
  -n server.example.com \
  -n www.example.com
```

### 3. 클라이언트 인증서 생성 (mTLS용)

```bash
# 스크립트 사용
./generate-client.sh ./certs my-client

# 또는 certgen 직접 사용
./certgen -t client \
  -s "/C=KR/O=MyOrg/CN=my-client" \
  -c ca-cert.pem \
  -K ca-key.pem \
  -o client-cert.pem \
  -k client-key.pem
```

## certgen 명령행 옵션

```
옵션:
  -t TYPE         인증서 타입 (ca, server, client)
  -a ALGORITHM    알고리즘 (dilithium3, dilithium5, rsa) [기본: dilithium3]
  -s SUBJECT      Subject DN (예: /C=KR/O=Example/CN=example.com)
  -d DAYS         유효 기간 (일) [기본: 365]
  -o CERT_FILE    출력 인증서 파일
  -k KEY_FILE     출력 키 파일
  -c CA_CERT      CA 인증서 (서버/클라이언트 인증서용)
  -K CA_KEY       CA 키 (서버/클라이언트 인증서용)
  -n SAN          Subject Alternative Name (서버 인증서용, 반복 가능)
  -h              도움말 표시
```

## 지원 알고리즘

- **dilithium3** (기본): NIST PQC 표준 (보안 레벨 3)
- **dilithium5**: NIST PQC 표준 (보안 레벨 5)
- **rsa**: RSA-2048/4096 (Fallback)

## 전체 예제

```bash
# 1. CA 생성
./generate-ca.sh ./certs

# 2. 서버 인증서 생성
./generate-server.sh ./certs myserver.local

# 3. 클라이언트 인증서 생성 (mTLS)
./generate-client.sh ./certs my-client

# 4. 인증서 확인
openssl x509 -in ./certs/server-cert.pem -text -noout
```

## 시스템 설치

```bash
sudo make install
```

설치 후 시스템 전역에서 사용 가능:
```bash
qtls-gen-ca ./certs
qtls-gen-server ./certs myserver.com
qtls-gen-client ./certs my-client
```

## 참고

- OpenSSL 3.x 이상 권장
- liboqs-openssl 통합 시 Dilithium 알고리즘 지원
- Dilithium 미지원 시 자동으로 RSA로 fallback
