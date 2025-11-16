# Q-TLS QSIGN Integration Example

QSIGN PKI, Luna HSM 및 엔터프라이즈 시스템 통합 예제

## 목차

1. [개요](#개요)
2. [아키텍처](#아키텍처)
3. [구성 요소](#구성-요소)
4. [빌드 및 설치](#빌드-및-설치)
5. [QSIGN PKI 설정](#qsign-pki-설정)
6. [Luna HSM 통합](#luna-hsm-통합)
7. [HashiCorp Vault 통합](#hashicorp-vault-통합)
8. [Apache APISIX 통합](#apache-apisix-통합)
9. [실행 가이드](#실행-가이드)
10. [프로덕션 배포](#프로덕션-배포)
11. [모니터링 및 운영](#모니터링-및-운영)
12. [문제 해결](#문제-해결)

## 개요

이 예제는 **QSIGN PKI 시스템**과 **Luna HSM**을 통합한 엔터프라이즈급 Q-TLS 서버 및 클라이언트를 구현합니다. 금융, 정부, 국방 등 높은 보안이 요구되는 환경에서 사용할 수 있는 완전한 솔루션을 제공합니다.

### 주요 특징

- **QSIGN PKI 통합**: 양자 내성 인증서 기반 PKI 시스템
- **Luna HSM 지원**: 하드웨어 보안 모듈을 통한 키 보호
- **상호 TLS 인증**: 클라이언트와 서버 양방향 인증
- **Vault 통합**: 인증서 동적 관리 및 자동 갱신
- **APISIX 게이트웨이**: API Gateway에서 Q-TLS 사용
- **엔터프라이즈 기능**: 감사 로깅, 모니터링, 고가용성

### 사용 사례

- **금융 시스템**: 거래 데이터 암호화 및 인증
- **정부/국방**: 기밀 통신 보호
- **의료 시스템**: 환자 정보 보호 (HIPAA 준수)
- **제로 트러스트 네트워크**: 모든 연결 인증 및 암호화
- **마이크로서비스**: 서비스 간 상호 인증 및 보안 통신

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        클라이언트 계층                           │
├─────────────────────────────────────────────────────────────────┤
│  웹 브라우저/모바일 앱 → HTTPS (TLS 1.3)                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   API Gateway (APISIX)                          │
├─────────────────────────────────────────────────────────────────┤
│  • Q-TLS 플러그인                                               │
│  • 로드 밸런싱                                                  │
│  • 속도 제한                                                    │
│  • API 키 인증                                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │ Q-TLS (Kyber1024 + Dilithium3)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Q-TLS 서버 클러스터                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Q-TLS Server │  │ Q-TLS Server │  │ Q-TLS Server │         │
│  │   (Node 1)   │  │   (Node 2)   │  │   (Node 3)   │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                  │                  │                 │
│         └──────────────────┴──────────────────┘                 │
│                            │                                     │
│         ┌──────────────────┴──────────────────┐                │
│         │        Luna HSM (PKCS#11)           │                │
│         │  • 개인키 저장                      │                │
│         │  • 암호화 연산                      │                │
│         │  • FIPS 140-2 Level 3               │                │
│         └─────────────────────────────────────┘                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      지원 시스템                                 │
├─────────────────────────────────────────────────────────────────┤
│  • QSIGN PKI (인증서 발급/검증)                                │
│  • HashiCorp Vault (인증서 관리)                               │
│  • Prometheus (메트릭 수집)                                     │
│  • Grafana (시각화)                                             │
│  • ELK Stack (로그 분석)                                        │
└─────────────────────────────────────────────────────────────────┘
```

## 구성 요소

### 1. qsign_server.c

QSIGN PKI 및 HSM 통합 서버

**주요 기능:**
- Luna HSM을 통한 개인키 보호
- QSIGN CA 인증서 체인 검증
- 클라이언트 상호 인증
- 세션 통계 및 감사 로깅
- 다중 클라이언트 처리

**사용 예:**
```bash
# HSM 사용 (프로덕션)
./qsign_server --hsm --hsm-pin <PIN> --port 8443

# 파일 기반 키 (테스트)
./qsign_server --port 8443 --key certs/server.key
```

### 2. qsign_client.c

QSIGN PKI 및 HSM 통합 클라이언트

**주요 기능:**
- 클라이언트 인증서 제공
- 서버 인증서 검증
- 대화형 메시지 전송
- 핸드셰이크 성능 측정

**사용 예:**
```bash
# HSM 사용
./qsign_client --host server.example.com --port 8443 --hsm --hsm-pin <PIN>

# 파일 기반 키
./qsign_client --host localhost --port 8443 --key certs/client.key
```

### 3. vault_integration.c

HashiCorp Vault 통합 예제

**주요 기능:**
- Vault PKI 시크릿 엔진 사용
- 동적 인증서 발급
- 인증서 자동 갱신
- Q-TLS 서버 설정 자동화

**사용 예:**
```bash
export VAULT_TOKEN="s.xxxxx"
./vault_integration --cn qtls-server.qsign.local
```

### 4. apisix_config.yaml

Apache APISIX Q-TLS 라우트 설정

**주요 내용:**
- Q-TLS 업스트림 정의
- 상호 TLS 인증 설정
- API 라우팅 및 보안 정책
- 성능 최적화 설정

## 빌드 및 설치

### 사전 요구사항

#### 필수 패키지

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    liboqs-dev \
    libcurl4-openssl-dev \
    libjansson-dev

# RHEL/CentOS
sudo yum install -y \
    gcc \
    cmake \
    openssl-devel \
    liboqs-devel \
    libcurl-devel \
    jansson-devel
```

#### Luna HSM (선택적, 프로덕션 권장)

Luna HSM 클라이언트 라이브러리 설치:
```bash
# Luna HSM 클라이언트 설치
# Thales Luna HSM 문서 참조
# https://thalesdocs.com/gphsm/luna/7/docs/network/Content/Home_Luna.htm

# PKCS#11 라이브러리 확인
ls /usr/lib/libCryptoki2_64.so
```

### Q-TLS 라이브러리 빌드

```bash
cd ../../
mkdir build && cd build
cmake .. -DENABLE_HSM=ON -DENABLE_EXAMPLES=ON
make
sudo make install
cd ../examples/qsign-integration
```

### 예제 빌드

```bash
# 기본 빌드 (HSM 없이)
make

# Vault 통합 포함
make all-with-vault

# 테스트 모드 빌드 (검증 완화)
make test-mode
```

## QSIGN PKI 설정

### QSIGN PKI 구조

```
QSIGN Root CA
├── Intermediate CA (Server)
│   ├── Server Certificate 1
│   ├── Server Certificate 2
│   └── Server Certificate 3
└── Intermediate CA (Client)
    ├── Client Certificate 1
    ├── Client Certificate 2
    └── Client Certificate 3
```

### PKI 초기 설정

#### 1. Root CA 생성

```bash
# QSIGN PKI 디렉토리 생성
sudo mkdir -p /etc/qsign/ca
sudo mkdir -p /etc/qsign/certs
sudo mkdir -p /etc/qsign/crl

# Root CA 개인키 생성 (HSM에서 생성 권장)
openssl genrsa -out /etc/qsign/ca/root-ca.key 4096

# Root CA 인증서 생성
openssl req -new -x509 -days 7300 \
    -key /etc/qsign/ca/root-ca.key \
    -out /etc/qsign/ca/root-ca.crt \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=QSIGN/OU=PKI/CN=QSIGN Root CA"
```

#### 2. Intermediate CA 생성

```bash
# Intermediate CA 개인키
openssl genrsa -out /etc/qsign/ca/intermediate-ca.key 4096

# CSR 생성
openssl req -new \
    -key /etc/qsign/ca/intermediate-ca.key \
    -out /etc/qsign/ca/intermediate-ca.csr \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=QSIGN/OU=PKI/CN=QSIGN Intermediate CA"

# Root CA로 서명
openssl x509 -req -days 3650 \
    -in /etc/qsign/ca/intermediate-ca.csr \
    -CA /etc/qsign/ca/root-ca.crt \
    -CAkey /etc/qsign/ca/root-ca.key \
    -CAcreateserial \
    -out /etc/qsign/ca/intermediate-ca.crt
```

#### 3. 서버 인증서 발급

```bash
# 서버 개인키 생성 (HSM 사용 권장)
openssl genrsa -out /etc/qsign/certs/server.key 4096

# CSR 생성
openssl req -new \
    -key /etc/qsign/certs/server.key \
    -out /etc/qsign/certs/server.csr \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=QSIGN/OU=Q-TLS/CN=qtls-server.qsign.local"

# Intermediate CA로 서명
openssl x509 -req -days 365 \
    -in /etc/qsign/certs/server.csr \
    -CA /etc/qsign/ca/intermediate-ca.crt \
    -CAkey /etc/qsign/ca/intermediate-ca.key \
    -CAcreateserial \
    -out /etc/qsign/certs/server.crt \
    -extfile <(printf "subjectAltName=DNS:qtls-server.qsign.local,DNS:*.qsign.local")
```

#### 4. 테스트 인증서 생성 (개발용)

```bash
make test-certs
```

### PKI 검증

```bash
# 인증서 체인 검증
openssl verify -CAfile /etc/qsign/ca/root-ca.crt \
    -untrusted /etc/qsign/ca/intermediate-ca.crt \
    /etc/qsign/certs/server.crt

# 인증서 정보 확인
openssl x509 -in /etc/qsign/certs/server.crt -noout -text
```

## Luna HSM 통합

### Luna HSM 설정

#### 1. HSM 초기화

```bash
# Luna HSM 슬롯 확인
/usr/safenet/lunaclient/bin/vtl verify

# 파티션 생성
lunacm
> partition create -partition qsign-server
> partition showInfo -partition qsign-server
```

#### 2. PKCS#11 설정

```bash
# Luna 클라이언트 설정
sudo /usr/safenet/lunaclient/bin/configurator

# 슬롯 정보 확인
pkcs11-tool --module /usr/lib/libCryptoki2_64.so --list-slots
```

#### 3. HSM에 키 생성

```bash
# PKCS#11 도구를 사용한 키 생성
pkcs11-tool --module /usr/lib/libCryptoki2_64.so \
    --login --pin <USER_PIN> \
    --keypairgen \
    --key-type RSA:4096 \
    --label "server-key" \
    --id 01
```

#### 4. Q-TLS 서버에서 HSM 키 사용

```bash
# HSM 모드로 서버 실행
./qsign_server --hsm --hsm-pin <USER_PIN> --port 8443
```

### HSM 성능 최적화

#### 연결 풀링 설정

`/etc/Chrystoki.conf`:
```ini
[LunaSA Client]
ServerCAFile = /usr/safenet/lunaclient/cert/server/CAFile.pem
ClientCertFile = /usr/safenet/lunaclient/cert/client/client.pem
ClientPrivKeyFile = /usr/safenet/lunaclient/cert/client/clientKey.pem

[Misc]
# 연결 풀 크기
ToolkitPoolSize = 50

# 세션 타임아웃 (초)
SessionTimeout = 300
```

## HashiCorp Vault 통합

### Vault PKI 설정

#### 1. Vault 서버 시작

```bash
# 개발 모드 (테스트용)
vault server -dev

# 프로덕션 모드
vault server -config=/etc/vault/config.hcl
```

#### 2. PKI 시크릿 엔진 활성화

```bash
# Vault 로그인
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='s.xxxxx'

# PKI 시크릿 엔진 활성화
vault secrets enable pki

# PKI 최대 TTL 설정
vault secrets tune -max-lease-ttl=87600h pki
```

#### 3. Root CA 생성

```bash
# 내부 Root CA 생성
vault write pki/root/generate/internal \
    common_name="QSIGN Vault Root CA" \
    ttl=87600h

# CA 인증서 확인
vault read pki/cert/ca
```

#### 4. PKI 역할 생성

```bash
# Q-TLS 서버 역할
vault write pki/roles/qtls-server \
    allowed_domains="qsign.local,example.com" \
    allow_subdomains=true \
    max_ttl=72h \
    key_type=rsa \
    key_bits=4096

# Q-TLS 클라이언트 역할
vault write pki/roles/qtls-client \
    allowed_domains="qsign.local" \
    allow_subdomains=true \
    max_ttl=24h \
    client_flag=true
```

#### 5. 동적 인증서 발급

```bash
# 서버 인증서 발급
vault write pki/issue/qtls-server \
    common_name="qtls-server.qsign.local" \
    ttl=24h

# 클라이언트 인증서 발급
vault write pki/issue/qtls-client \
    common_name="qtls-client.qsign.local" \
    ttl=24h
```

### Vault 통합 예제 실행

```bash
# 환경 변수 설정
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='s.xxxxx'

# Vault 통합 예제 빌드
make all-with-vault

# 인증서 발급 및 서버 설정
./vault_integration --token $VAULT_TOKEN \
    --cn qtls-server.qsign.local

# 인증서 갱신 시뮬레이션
./vault_integration --token $VAULT_TOKEN --renewal
```

### 자동 인증서 갱신

#### Systemd 타이머 설정

`/etc/systemd/system/qtls-cert-renewal.service`:
```ini
[Unit]
Description=Q-TLS Certificate Renewal
After=network.target vault.service

[Service]
Type=oneshot
User=qtls
ExecStart=/usr/local/bin/vault_integration --token file:///etc/qtls/vault-token --renewal
```

`/etc/systemd/system/qtls-cert-renewal.timer`:
```ini
[Unit]
Description=Q-TLS Certificate Renewal Timer

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

활성화:
```bash
sudo systemctl enable qtls-cert-renewal.timer
sudo systemctl start qtls-cert-renewal.timer
```

## Apache APISIX 통합

### APISIX 설치

#### Docker Compose 사용

`docker-compose-apisix.yml`:
```yaml
version: "3"

services:
  apisix:
    image: apache/apisix:latest
    restart: always
    volumes:
      - ./apisix_config.yaml:/usr/local/apisix/conf/config.yaml:ro
      - ./logs:/usr/local/apisix/logs
    ports:
      - "9080:9080"
      - "9443:9443"
      - "9180:9180"
    environment:
      - APISIX_ADMIN_KEY=edd1c9f034335f136f87ad84b625c8f1

  etcd:
    image: bitnami/etcd:latest
    restart: always
    environment:
      - ALLOW_NONE_AUTHENTICATION=yes
      - ETCD_ADVERTISE_CLIENT_URLS=http://etcd:2379
    ports:
      - "2379:2379"
```

#### 시작

```bash
docker-compose -f docker-compose-apisix.yml up -d
```

### Q-TLS 라우트 설정

#### 1. APISIX 설정 검증

```bash
make validate-apisix
```

#### 2. APISIX에 라우트 배포

```bash
export APISIX_ADMIN_KEY="edd1c9f034335f136f87ad84b625c8f1"
make deploy-apisix
```

#### 3. 라우트 테스트

```bash
# API 요청
curl -k https://api.qsign.local/api/v1/test \
    -H "apikey: qsign-app-1-key-xxxxx"

# 관리자 API
curl -k https://admin.qsign.local/admin/status \
    -H "Authorization: Bearer <token>"
```

### APISIX 모니터링

#### Prometheus 메트릭 확인

```bash
curl http://127.0.0.1:9091/apisix/prometheus/metrics | grep qtls
```

예상 메트릭:
```
qtls_handshake_duration_seconds{route="qtls-secure-api"} 0.15
qtls_connections_total{route="qtls-secure-api"} 1234
qtls_bytes_sent{route="qtls-secure-api"} 567890
qtls_bytes_received{route="qtls-secure-api"} 123456
```

## 실행 가이드

### 테스트 환경 (HSM 없이)

#### 1. 테스트 인증서 생성

```bash
make test-certs
```

#### 2. 서버 시작

터미널 1:
```bash
make run-server
```

출력:
```
=======================================================
  Q-TLS QSIGN Integration Server
  QSIGN PKI 및 Luna HSM 통합 서버
=======================================================
Q-TLS 버전: 1.0.0

[INFO] 테스트 모드: 파일 기반 키 사용

[INFO] Q-TLS 서버 컨텍스트 초기화 중...
[INFO] 하이브리드 PQC 모드 활성화
[INFO] 클라이언트 인증서 검증 활성화 (상호 인증 모드)
[INFO] QSIGN CA 인증서 로드 완료
[INFO] PQC 알고리즘 설정: Kyber1024+ECDHE, Dilithium3+ECDSA
[INFO] 서버 소켓 생성 완료: 포트 8443 (백로그: 128)

╔═══════════════════════════════════════════════════════╗
║  QSIGN Q-TLS 서버 시작                              ║
╠═══════════════════════════════════════════════════════╣
║  포트: 8443                                          ║
║  HSM: 비활성화                                       ║
║  인증 모드: 상호 TLS (mTLS)                         ║
║  PQC: Kyber1024 + Dilithium3                        ║
╚═══════════════════════════════════════════════════════╝

[INFO] 클라이언트 연결 대기 중... (Ctrl+C로 종료)
```

#### 3. 클라이언트 실행

터미널 2:
```bash
make run-client
```

대화형 메시지:
```
메시지> Hello, Q-TLS!
[SENT] 16 바이트
[RECV] QSIGN 서버 응답 [세션 #1]: 메시지 수신 완료 (16 바이트)

메시지> Test message
[SENT] 12 바이트
[RECV] QSIGN 서버 응답 [세션 #1]: 메시지 수신 완료 (12 바이트)

메시지> quit
[INFO] 연결 종료 중...

[SUCCESS] 통신 완료
```

### 프로덕션 환경 (HSM 사용)

#### 1. Luna HSM 확인

```bash
# HSM 상태 확인
/usr/safenet/lunaclient/bin/vtl verify

# 슬롯 및 토큰 확인
pkcs11-tool --module /usr/lib/libCryptoki2_64.so --list-slots
```

#### 2. 서버 시작 (HSM 모드)

```bash
make run-server-prod
```

HSM PIN 입력 프롬프트:
```
HSM PIN: ********
```

#### 3. 클라이언트 실행 (HSM 모드)

```bash
make run-client-prod
```

### 성능 테스트

```bash
# 벤치마크 실행
make benchmark
```

벤치마크 스크립트는 다음을 측정합니다:
- 핸드셰이크 시간
- 초당 요청 수 (RPS)
- 처리량 (Throughput)
- CPU 및 메모리 사용량

## 프로덕션 배포

### 시스템 요구사항

#### 하드웨어

- **CPU**: 4+ 코어 (AES-NI 지원 권장)
- **RAM**: 8GB+ (HSM 사용 시 16GB+)
- **디스크**: SSD 100GB+
- **네트워크**: 1Gbps+

#### 소프트웨어

- **OS**: Ubuntu 20.04 LTS / RHEL 8+
- **커널**: 5.4+
- **OpenSSL**: 1.1.1+
- **liboqs**: latest
- **Luna HSM**: Client 7.4+

### 배포 아키텍처

#### 고가용성 구성

```
                    Load Balancer (HAProxy)
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   Q-TLS Server 1      Q-TLS Server 2     Q-TLS Server 3
        │                   │                   │
        └───────────────────┴───────────────────┘
                            │
                    Luna HSM Cluster
                    (Active-Active)
```

#### HAProxy 설정

`/etc/haproxy/haproxy.cfg`:
```
frontend qtls-frontend
    bind *:8443 ssl crt /etc/ssl/certs/haproxy.pem
    mode tcp
    default_backend qtls-backend

backend qtls-backend
    mode tcp
    balance roundrobin
    option tcp-check

    server qtls1 10.0.1.10:8443 check
    server qtls2 10.0.1.11:8443 check
    server qtls3 10.0.1.12:8443 check backup
```

### Systemd 서비스 설정

`/etc/systemd/system/qsign-qtls.service`:
```ini
[Unit]
Description=QSIGN Q-TLS Server
After=network.target luna-hsm.service

[Service]
Type=simple
User=qtls
Group=qtls
WorkingDirectory=/opt/qsign/qtls
Environment="LD_LIBRARY_PATH=/usr/local/lib"
ExecStart=/opt/qsign/qtls/bin/qsign_server \
    --hsm \
    --hsm-pin file:///etc/qsign/hsm-pin \
    --port 8443

# 보안 설정
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/qsign

# 리소스 제한
LimitNOFILE=65536
LimitNPROC=512

# 자동 재시작
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

활성화:
```bash
sudo systemctl enable qsign-qtls.service
sudo systemctl start qsign-qtls.service
sudo systemctl status qsign-qtls.service
```

### 보안 강화

#### 1. 파일 권한 설정

```bash
# 인증서 및 키 권한
sudo chown -R qtls:qtls /etc/qsign
sudo chmod 700 /etc/qsign/certs
sudo chmod 600 /etc/qsign/certs/*.key
sudo chmod 644 /etc/qsign/certs/*.crt
```

#### 2. SELinux 정책 (RHEL/CentOS)

```bash
# SELinux 컨텍스트 설정
sudo semanage fcontext -a -t bin_t "/opt/qsign/qtls/bin/qsign_server"
sudo restorecon -v /opt/qsign/qtls/bin/qsign_server

# HSM 라이브러리 접근 허용
sudo setsebool -P allow_execmem on
```

#### 3. 방화벽 설정

```bash
# UFW (Ubuntu)
sudo ufw allow 8443/tcp
sudo ufw enable

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

## 모니터링 및 운영

### Prometheus 메트릭

#### Q-TLS 메트릭 엔드포인트 추가

서버 코드에 메트릭 수집 추가:
```c
// qsign_server.c에 추가
void export_prometheus_metrics(void) {
    FILE *fp = fopen("/var/lib/qsign/metrics.prom", "w");
    if (!fp) return;

    fprintf(fp, "# HELP qtls_sessions_total Total number of sessions\n");
    fprintf(fp, "# TYPE qtls_sessions_total counter\n");
    fprintf(fp, "qtls_sessions_total %lu\n", session_counter);

    fprintf(fp, "# HELP qtls_bytes_received_total Total bytes received\n");
    fprintf(fp, "# TYPE qtls_bytes_received_total counter\n");
    fprintf(fp, "qtls_bytes_received_total %lu\n", total_bytes_received);

    fprintf(fp, "# HELP qtls_bytes_sent_total Total bytes sent\n");
    fprintf(fp, "# TYPE qtls_bytes_sent_total counter\n");
    fprintf(fp, "qtls_bytes_sent_total %lu\n", total_bytes_sent);

    fclose(fp);
}
```

#### Prometheus 설정

`/etc/prometheus/prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'qtls-servers'
    static_configs:
      - targets:
          - '10.0.1.10:9090'
          - '10.0.1.11:9090'
          - '10.0.1.12:9090'
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana 대시보드

#### 대시보드 JSON 가져오기

주요 패널:
- **세션 통계**: 총 세션 수, 활성 세션
- **처리량**: 초당 바이트 송수신
- **성능**: 핸드셰이크 시간, 응답 시간
- **오류율**: 핸드셰이크 실패, 인증 실패
- **HSM 상태**: HSM 연결, 키 사용률

### 로그 관리

#### Syslog 설정

`/etc/rsyslog.d/qtls.conf`:
```
# Q-TLS 로그를 별도 파일로 저장
if $programname == 'qsign-qtls' then /var/log/qsign/qtls.log
& stop
```

#### ELK Stack 통합

Filebeat 설정 (`/etc/filebeat/filebeat.yml`):
```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/qsign/qtls.log
    fields:
      service: qtls
      environment: production

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "qtls-%{+yyyy.MM.dd}"
```

### 알림 설정

#### Prometheus Alertmanager

`/etc/prometheus/alert.rules.yml`:
```yaml
groups:
  - name: qtls_alerts
    interval: 30s
    rules:
      - alert: HighHandshakeFailureRate
        expr: rate(qtls_handshake_failures_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High Q-TLS handshake failure rate"
          description: "Handshake failure rate is above 10%"

      - alert: HSMConnectionLost
        expr: qtls_hsm_connected == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "HSM connection lost"
          description: "Q-TLS server lost connection to Luna HSM"

      - alert: CertificateExpiringSoon
        expr: (qtls_cert_expiry_seconds - time()) < 86400 * 7
        labels:
          severity: warning
        annotations:
          summary: "Certificate expiring soon"
          description: "Certificate expires in less than 7 days"
```

## 문제 해결

### 일반적인 문제

#### 1. HSM 연결 실패

**증상:**
```
[ERROR] HSM 초기화 실패: QTLS_ERROR_HSM_INIT_FAILED
```

**해결:**
```bash
# HSM 클라이언트 상태 확인
/usr/safenet/lunaclient/bin/vtl verify

# 네트워크 연결 확인
ping <hsm-ip>
telnet <hsm-ip> 1792

# 클라이언트 인증서 확인
ls -l /usr/safenet/lunaclient/cert/client/

# 로그 확인
tail -f /var/log/luna/lunacm.log
```

#### 2. 인증서 검증 실패

**증상:**
```
[ERROR] 클라이언트 인증서 검증 실패
```

**해결:**
```bash
# 인증서 체인 확인
openssl verify -CAfile /etc/qsign/ca/root-ca.crt \
    -untrusted /etc/qsign/ca/intermediate-ca.crt \
    /etc/qsign/certs/client.crt

# 인증서 만료 확인
openssl x509 -in /etc/qsign/certs/client.crt -noout -dates

# CRL 확인
openssl crl -in /etc/qsign/crl/revoked.crl -noout -text
```

#### 3. 성능 저하

**증상:**
- 핸드셰이크 시간 > 1초
- 낮은 RPS

**진단:**
```bash
# CPU 사용률 확인
top
htop

# HSM 성능 확인
# Luna HSM 콘솔에서 성능 메트릭 확인

# 네트워크 지연 확인
ping -c 100 <server-ip>
mtr <server-ip>

# 스레드 및 연결 수 확인
ss -s
netstat -an | grep 8443 | wc -l
```

**해결:**
- HSM 연결 풀 크기 증가
- 서버 인스턴스 추가 (로드 밸런싱)
- 세션 재개 활성화
- CPU 업그레이드 (AES-NI 지원)

### 디버깅

#### 상세 로깅 활성화

```bash
# 서버 실행 시 디버그 로그 활성화
export QTLS_LOG_LEVEL=DEBUG
./qsign_server --port 8443 --key certs/server.key
```

#### 네트워크 트래픽 캡처

```bash
# tcpdump로 Q-TLS 트래픽 캡처
sudo tcpdump -i any -w qtls.pcap port 8443

# Wireshark에서 분석
wireshark qtls.pcap
```

#### 코어 덤프 분석

```bash
# 코어 덤프 활성화
ulimit -c unlimited

# 크래시 발생 시 gdb로 분석
gdb ./qsign_server core
(gdb) bt full
```

## 참고 자료

### 문서

- [Q-TLS API 문서](../../docs/API.md)
- [QSIGN PKI 가이드](https://qsign.io/docs/pki)
- [Luna HSM 문서](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/Home_Luna.htm)
- [HashiCorp Vault PKI](https://www.vaultproject.io/docs/secrets/pki)
- [Apache APISIX 문서](https://apisix.apache.org/docs/apisix/getting-started/)

### 표준

- [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber Specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
- [Dilithium Specification](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)
- [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
- [PKCS#11 v2.40](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)

### 커뮤니티

- [QSIGN GitHub](https://github.com/qsign)
- [Q-TLS Issues](https://github.com/qsign/Q-TLS/issues)
- [QSIGN 포럼](https://forum.qsign.io)

## 라이선스

Apache License 2.0 - 자세한 내용은 프로젝트 루트의 LICENSE 파일 참조

---

**작성일**: 2025-11-16
**버전**: 1.0.0
**작성자**: QSIGN Project Team
