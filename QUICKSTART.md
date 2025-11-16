# Q-TLS 빠른 시작 가이드

OpenSSL처럼 쉽게 사용할 수 있는 Q-TLS CLI 도구 사용법입니다.

## 1분 안에 시작하기

### 의존성 설치 및 빌드

```bash
# 1. 의존성 설치 (liboqs, OpenSSL 등)
./scripts/install-deps.sh

# 2. 전체 프로젝트 빌드
./scripts/build.sh

# 3. CLI 도구 빌드
cd tools
make

# 4. (선택) 시스템 설치
sudo make install
```

### 또는 스크립트 버전 사용

빌드 없이 바로 사용 가능한 Bash 스크립트 버전:

```bash
./tools/qtls.sh quickstart -d ./my-pki
```

## 30초 안에 전체 PKI 구축

```bash
# CA + 서버 + 클라이언트 인증서 한 번에 생성
qtls quickstart -d ./my-pki

# 또는 빌드 전이면
./tools/qtls.sh quickstart -d ./my-pki
```

생성되는 파일:
```
my-pki/
├── ca.crt              # CA 인증서
├── ca.key              # CA 개인키
├── server.crt          # 서버 인증서
├── server.key          # 서버 개인키
├── client.crt          # 클라이언트 인증서
├── client.key          # 클라이언트 개인키
└── README.txt          # 사용 가이드
```

### 권한 설정

```bash
chmod 600 ./my-pki/*.key
chmod 644 ./my-pki/*.crt
```

## OpenSSL 스타일 명령어

### 키 생성

```bash
# Kyber768 KEM 키 생성 (권장)
qtls keygen kyber768 -o mykey
# → mykey.pub, mykey.key 생성

# Dilithium3 서명 키 생성 (권장)
qtls keygen dilithium3 -o signing-key

# 다른 알고리즘
qtls keygen kyber512 -o fast-key      # 빠른 속도
qtls keygen kyber1024 -o secure-key   # 최고 보안
qtls keygen dilithium5 -o max-sec     # 최고 보안 서명
```

### CA 인증서 생성

```bash
# 기본 CA (10년 유효)
qtls certgen ca -cn "My Root CA" -o ca

# 또는 직접 certgen 사용
certgen -t ca \
  -s "/C=KR/O=MyCompany/CN=My Root CA" \
  -d 3650 \
  -o ca.crt \
  -k ca.key
```

### 서버 인증서 생성

```bash
# 기본 서버 인증서
qtls certgen server \
  -cn server.example.com \
  --ca-cert ca.crt \
  --ca-key ca.key \
  -o server

# 여러 도메인 (SAN) 추가
certgen -t server \
  -s "/C=KR/O=MyCompany/CN=api.example.com" \
  -c ca.crt \
  -K ca.key \
  -o server.crt \
  -k server.key \
  -n api.example.com \
  -n www.example.com \
  -n *.api.example.com
```

### 클라이언트 인증서 생성

```bash
# mTLS용 클라이언트 인증서
qtls certgen client \
  -cn "client-001" \
  --ca-cert ca.crt \
  --ca-key ca.key \
  -o client

# 또는 직접 certgen 사용
certgen -t client \
  -s "/C=KR/O=MyCompany/CN=client-001" \
  -c ca.crt \
  -K ca.key \
  -o client.crt \
  -k client.key
```

## 실전 예제

### 예제 1: localhost 개발 환경

```bash
# 1. 개발용 PKI 생성
qtls quickstart -d ~/.qtls/dev -cn localhost

# 2. 서버 실행 (Q-TLS 예제)
cd examples/simple-server
./simple_server \
  --cert ~/.qtls/dev/server.crt \
  --key ~/.qtls/dev/server.key \
  --ca ~/.qtls/dev/ca.crt \
  --port 8443

# 3. 클라이언트 연결
cd examples/simple-client
./simple_client \
  --ca ~/.qtls/dev/ca.crt \
  --host localhost \
  --port 8443
```

### 예제 2: 상호 TLS (mTLS)

```bash
# 1. PKI 생성
qtls quickstart -d ./mtls

# 2. 추가 클라이언트 인증서 생성
certgen -t client \
  -s "/C=KR/O=MyApp/CN=mobile-app" \
  -c ./mtls/ca.crt \
  -K ./mtls/ca.key \
  -o ./mtls/mobile.crt \
  -k ./mtls/mobile.key

# 3. mTLS 서버 실행
cd examples/mutual-tls
./mtls_server \
  --cert ../../mtls/server.crt \
  --key ../../mtls/server.key \
  --ca ../../mtls/ca.crt \
  --verify-client

# 4. mTLS 클라이언트 연결
./mtls_client \
  --cert ../../mtls/mobile.crt \
  --key ../../mtls/mobile.key \
  --ca ../../mtls/ca.crt
```

### 예제 3: 프로덕션 환경

```bash
# 1. 고보안 CA 생성 (Dilithium5, 20년)
certgen -t ca \
  -a dilithium5 \
  -s "/C=KR/O=ProductionCA/CN=Prod Root CA" \
  -d 7300 \
  -o /secure/ca.crt \
  -k /secure/ca.key

# 2. 프로덕션 서버 인증서 (1년)
certgen -t server \
  -a dilithium5 \
  -s "/C=KR/O=MyCompany/CN=prod.example.com" \
  -c /secure/ca.crt \
  -K /secure/ca.key \
  -d 365 \
  -n prod.example.com \
  -n *.prod.example.com \
  -o /secure/prod-server.crt \
  -k /secure/prod-server.key

# 3. CA 키를 안전하게 백업하고 오프라인 보관
gpg -c /secure/ca.key
mv /secure/ca.key /offline-backup/

# 4. 권한 설정
chmod 600 /secure/*.key
chmod 644 /secure/*.crt
chown root:ssl-cert /secure/*
```

### 예제 4: 여러 클라이언트 인증서 생성

```bash
# 1. CA 생성
qtls certgen ca -cn "Multi-Client CA" -o ca

# 2. 10개 클라이언트 인증서 생성
for i in {1..10}; do
  certgen -t client \
    -s "/C=KR/O=Clients/CN=client-$(printf %03d $i)" \
    -c ca.crt \
    -K ca.key \
    -o client-$(printf %03d $i).crt \
    -k client-$(printf %03d $i).key
done

# 3. 인증서 목록 확인
for cert in client-*.crt; do
  echo "=== $cert ==="
  openssl x509 -in "$cert" -noout -subject
done
```

## 인증서 검증 및 정보 확인

### 인증서 정보 보기

```bash
# OpenSSL 사용
openssl x509 -in server.crt -text -noout

# 또는 qtls info (구현 예정)
qtls info server.crt
```

### 인증서 체인 검증

```bash
# 서버 인증서가 CA로 서명되었는지 확인
openssl verify -CAfile ca.crt server.crt

# 클라이언트 인증서 검증
openssl verify -CAfile ca.crt client.crt
```

### 인증서 만료일 확인

```bash
openssl x509 -in server.crt -noout -dates
```

### 개인키와 인증서 매칭 확인

```bash
# 인증서의 공개키 해시
openssl x509 -in server.crt -noout -modulus | openssl md5

# 개인키의 공개키 해시
openssl rsa -in server.key -noout -modulus | openssl md5

# 두 해시가 같으면 매칭됨
```

## Bash 자동완성

```bash
# 자동완성 활성화
echo "source $(pwd)/tools/qtls-completion.bash" >> ~/.bashrc
source ~/.bashrc

# 사용
qtls <TAB><TAB>           # 명령어 목록
qtls keygen <TAB><TAB>    # 알고리즘 목록
qtls certgen <TAB><TAB>   # 인증서 타입
```

## 알고리즘 선택 가이드

### 일반 용도 (권장)

```bash
# KEM: Kyber768
qtls keygen kyber768 -o key

# 서명: Dilithium3
qtls certgen ca -cn "My CA" -a dilithium3 -o ca
```

### 성능 최적화 (IoT, 임베디드)

```bash
# KEM: Kyber512
qtls keygen kyber512 -o fast-key

# 서명: Dilithium2
qtls certgen ca -cn "IoT CA" -a dilithium2 -o iot-ca
```

### 최고 보안 (장기 보관, 규제 준수)

```bash
# KEM: Kyber1024
qtls keygen kyber1024 -o secure-key

# 서명: Dilithium5
qtls certgen ca -cn "Secure CA" -a dilithium5 -o secure-ca
```

## 문제 해결

### "command not found: qtls"

```bash
# 빌드 및 설치
cd tools
make
sudo make install

# 또는 스크립트 버전 사용
./tools/qtls.sh quickstart -d ./pki
```

### "command not found: certgen"

```bash
# certgen 빌드
cd tools/certgen
make
sudo make install
```

### "command not found: keygen"

```bash
# keygen 빌드
cd tools/keygen
make
sudo make install
```

### liboqs 오류

```bash
# liboqs 설치
./scripts/install-deps.sh

# 또는 수동 설치
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

## 다음 단계

1. **테스트 실행**: `./scripts/run-all-tests.sh`
2. **예제 실행**: `cd examples/simple-server && make && ./simple_server`
3. **문서 읽기**: `docs/API-REFERENCE.md`, `docs/SECURITY.md`
4. **QSIGN 통합**: `docs/QSIGN-INTEGRATION.md`

## 참고

- [상세 매뉴얼](tools/README.md)
- [API 문서](docs/API-REFERENCE.md)
- [보안 가이드](docs/SECURITY.md)
- [성능 분석](docs/PERFORMANCE.md)
