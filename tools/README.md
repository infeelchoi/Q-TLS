# Q-TLS CLI 통합 도구

OpenSSL처럼 사용하기 쉬운 양자 내성 암호화 CLI 도구입니다.

## 빌드 및 설치

```bash
# 빌드
make

# 시스템 설치
sudo make install

# Bash 자동완성 활성화 (선택)
echo "source $(pwd)/qtls-completion.bash" >> ~/.bashrc
source ~/.bashrc
```

## 빠른 시작 (30초 안에 전체 PKI 구축)

```bash
# CA + 서버 + 클라이언트 인증서 한 번에 생성
qtls quickstart -d ./my-pki

# 생성된 파일 확인
ls -la ./my-pki/
# ca.crt, ca.key
# server.crt, server.key
# client.crt, client.key
# README.txt

# 권한 설정
chmod 600 ./my-pki/*.key
```

## 명령어 사용법

### 1. 키 생성 (keygen)

#### Kyber KEM 키 생성

```bash
# Kyber768 (권장)
qtls keygen kyber768 -o mykey
# → mykey.pub, mykey.key 생성

# Kyber512 (빠른 속도)
qtls keygen kyber512 -o fast-key

# Kyber1024 (최고 보안)
qtls keygen kyber1024 -o secure-key

# 특정 디렉토리에 생성
qtls keygen kyber768 -o session-key -d ./keys/
```

#### Dilithium 서명 키 생성

```bash
# Dilithium3 (권장)
qtls keygen dilithium3 -o signing-key

# Dilithium2 (빠른 속도)
qtls keygen dilithium2 -o fast-sig

# Dilithium5 (최고 보안)
qtls keygen dilithium5 -o secure-sig
```

### 2. 인증서 생성 (certgen)

#### CA 인증서 생성

```bash
# 기본 CA
qtls certgen ca -cn "My Root CA" -o ca

# 10년 유효 CA
qtls certgen ca -cn "My Root CA" -o ca --days 3650

# Dilithium5 알고리즘 사용
qtls certgen ca -cn "Secure CA" -a dilithium5 -o secure-ca
```

#### 서버 인증서 생성

```bash
# 기본 서버 인증서
qtls certgen server \
  -cn server.example.com \
  --ca-cert ca.crt \
  --ca-key ca.key \
  -o server

# 여러 도메인 (SAN) 추가
qtls certgen server \
  -cn api.example.com \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --san www.example.com \
  --san *.api.example.com \
  --san localhost \
  -o api-server

# localhost 개발용
qtls certgen server \
  -cn localhost \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --san 127.0.0.1 \
  --san ::1 \
  -o localhost-server
```

#### 클라이언트 인증서 생성 (상호 TLS)

```bash
# 기본 클라이언트 인증서
qtls certgen client \
  -cn "client-001" \
  --ca-cert ca.crt \
  --ca-key ca.key \
  -o client-001

# 여러 클라이언트 생성
for i in {1..10}; do
  qtls certgen client \
    -cn "client-$(printf %03d $i)" \
    --ca-cert ca.crt \
    --ca-key ca.key \
    -o client-$(printf %03d $i)
done
```

### 3. 빠른 시작 (quickstart)

```bash
# 기본 설정 (localhost)
qtls quickstart

# 커스텀 서버 이름
qtls quickstart -cn myserver.local

# 특정 디렉토리에 생성
qtls quickstart -d ~/certificates/prod

# Dilithium5 알고리즘 사용
qtls quickstart -a dilithium5 -d ./secure-pki

# 상세 출력
qtls quickstart -v
```

## 실전 예제

### 예제 1: 웹 서버용 인증서 생성

```bash
# 1. CA 생성
qtls certgen ca -cn "MyCompany Root CA" -o company-ca

# 2. 웹 서버 인증서 생성
qtls certgen server \
  -cn www.mycompany.com \
  --ca-cert company-ca.crt \
  --ca-key company-ca.key \
  --san www.mycompany.com \
  --san mycompany.com \
  --san api.mycompany.com \
  -o web-server

# 3. 권한 설정
chmod 600 *.key
chmod 644 *.crt

# 4. Nginx에서 사용
# ssl_certificate     /path/to/web-server.crt;
# ssl_certificate_key /path/to/web-server.key;
# ssl_client_certificate /path/to/company-ca.crt;
```

### 예제 2: mTLS (상호 인증) 설정

```bash
# 1. 전체 PKI 생성
qtls quickstart -d ./mtls-pki

# 2. 추가 클라이언트 인증서 생성
qtls certgen client \
  -cn "mobile-app" \
  --ca-cert ./mtls-pki/ca.crt \
  --ca-key ./mtls-pki/ca.key \
  -o ./mtls-pki/mobile-client

# 3. 서버 설정 (Q-TLS)
qtls-server \
  --cert ./mtls-pki/server.crt \
  --key ./mtls-pki/server.key \
  --ca ./mtls-pki/ca.crt \
  --verify-client

# 4. 클라이언트 연결
qtls-client \
  --cert ./mtls-pki/client.crt \
  --key ./mtls-pki/client.key \
  --ca ./mtls-pki/ca.crt \
  --host localhost
```

### 예제 3: 개발 환경 설정

```bash
# 개발용 PKI 구축
qtls quickstart -d ~/.qtls/dev -cn localhost

# 환경 변수 설정
export QTLS_CA_CERT=~/.qtls/dev/ca.crt
export QTLS_SERVER_CERT=~/.qtls/dev/server.crt
export QTLS_SERVER_KEY=~/.qtls/dev/server.key

# 개발 서버 실행
qtls-server --cert $QTLS_SERVER_CERT --key $QTLS_SERVER_KEY
```

### 예제 4: 프로덕션 배포

```bash
# 프로덕션 PKI (Dilithium5 최고 보안)
qtls certgen ca \
  -cn "Production Root CA" \
  -a dilithium5 \
  --days 7300 \
  -o prod-ca \
  -d /secure/certs/

# 프로덕션 서버 인증서 (1년 유효)
qtls certgen server \
  -cn prod.mycompany.com \
  -a dilithium5 \
  --ca-cert /secure/certs/prod-ca.crt \
  --ca-key /secure/certs/prod-ca.key \
  --days 365 \
  --san prod.mycompany.com \
  --san *.prod.mycompany.com \
  -o prod-server \
  -d /secure/certs/

# CA 키는 안전한 곳에 백업 후 오프라인 보관
gpg -c /secure/certs/prod-ca.key
mv /secure/certs/prod-ca.key /offline/backup/
```

## 명령어 참조

### keygen

```
사용법: qtls keygen <알고리즘> [옵션]

알고리즘:
  kyber512, kyber768, kyber1024      (KEM)
  dilithium2, dilithium3, dilithium5 (서명)

옵션:
  -o, --output NAME    출력 파일명
  -d, --dir PATH       출력 디렉토리
  -v, --verbose        상세 출력
  -h, --help           도움말
```

### certgen

```
사용법: qtls certgen <타입> [옵션]

타입:
  ca         CA 인증서
  server     서버 인증서
  client     클라이언트 인증서

옵션:
  -cn, --common-name NAME  Common Name (필수)
  -o, --output NAME        출력 파일명
  -d, --dir PATH           출력 디렉토리
  -a, --algorithm ALG      알고리즘 (dilithium3, dilithium5, rsa)
  --days DAYS              유효 기간
  --ca-cert PATH           CA 인증서 경로
  --ca-key PATH            CA 키 경로
  --san DOMAIN             SAN 도메인 (반복 가능)
  -v, --verbose            상세 출력
  -h, --help               도움말
```

### quickstart

```
사용법: qtls quickstart [옵션]

옵션:
  -d, --dir PATH           출력 디렉토리 (기본: ./qtls-pki)
  -cn, --server-cn NAME    서버 CN (기본: localhost)
  -a, --algorithm ALG      알고리즘 (기본: dilithium3)
  -v, --verbose            상세 출력
  -h, --help               도움말
```

## 알고리즘 선택 가이드

### KEM (키 캡슐화)

| 알고리즘 | 보안 레벨 | 속도 | 키 크기 | 권장 용도 |
|---------|----------|------|---------|---------|
| Kyber512 | 1 | 빠름 | 작음 | IoT, 임베디드 |
| **Kyber768** | **3** | **보통** | **보통** | **일반 용도 (권장)** |
| Kyber1024 | 5 | 느림 | 큼 | 최고 보안 필요 |

### 서명

| 알고리즘 | 보안 레벨 | 속도 | 서명 크기 | 권장 용도 |
|---------|----------|------|-----------|---------|
| Dilithium2 | 2 | 빠름 | 작음 | 성능 중시 |
| **Dilithium3** | **3** | **보통** | **보통** | **일반 용도 (권장)** |
| Dilithium5 | 5 | 느림 | 큼 | 장기 보관, 규제 준수 |

## Bash 자동완성

```bash
# 설치
echo "source /path/to/qtls-completion.bash" >> ~/.bashrc
source ~/.bashrc

# 사용
qtls <TAB>           # 명령어 목록
qtls keygen <TAB>    # 알고리즘 목록
qtls certgen <TAB>   # 인증서 타입 목록
```

## 문제 해결

### "certgen: command not found"

```bash
# certgen 도구 빌드 및 설치
cd tools/certgen
make
sudo make install
```

### "keygen: command not found"

```bash
# keygen 도구 빌드 및 설치
cd tools/keygen
make
sudo make install
```

### liboqs 관련 오류

```bash
# liboqs 설치
../../scripts/install-deps.sh
```

## 관련 도구

- `tools/keygen/` - 독립 실행형 키 생성 도구
- `tools/certgen/` - 독립 실행형 인증서 생성 도구
- `tools/benchmark/` - 성능 벤치마크 도구
- `scripts/` - 빌드 및 테스트 자동화 스크립트

## 라이선스

Q-TLS Project License
