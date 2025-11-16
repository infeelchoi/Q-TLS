# Keycloak용 Q-TLS 제공자

## 개요

Q-TLS 제공자는 Keycloak Identity and Access Management (IAM) 시스템에 양자 내성 암호화를 통합합니다. 이 통합을 통해 Keycloak은 안전한 인증을 위해 양자 후 암호화 알고리즘(KYBER1024 및 DILITHIUM3)을 사용하여 기존 및 양자 위협 모두로부터 보호합니다.

## 기능

- **양자 내성 인증**: KYBER1024 키 교환 및 DILITHIUM3 서명
- **하이브리드 암호화**: 심층 방어를 위한 기존 및 PQC 알고리즘 결합
- **Luna HSM 통합**: PKCS#11을 통한 안전한 키 저장소
- **X.509 클라이언트 인증서**: QSIGN PKI 하이브리드 인증서 지원
- **상호 TLS**: 향상된 보안을 위한 클라이언트 인증서 검증
- **FIPS 140-2 준수**: 활성화 시 FIPS 검증 암호화 모듈 사용
- **OIDC/SAML 통합**: 표준 인증 프로토콜과 함께 작동
- **세션 보안**: 양자 내성 세션 토큰 보호

## 아키텍처

```
┌──────────────────────────────────────────┐
│         Keycloak 서버                     │
│  ┌────────────────────────────────────┐  │
│  │   Q-TLS 제공자 (Java/JNA)          │  │
│  │  ┌──────────────────────────────┐  │  │
│  │  │  QTLSProvider.java           │  │  │
│  │  │  - SSLContext                │  │  │
│  │  │  - X.509 검증                │  │  │
│  │  │  - QSIGN PKI 통합            │  │  │
│  │  └──────────┬───────────────────┘  │  │
│  │             │ JNA                   │  │
│  │  ┌──────────▼───────────────────┐  │  │
│  │  │  libqtls.so (Q-TLS 라이브러리)│  │  │
│  │  │  - KYBER1024                 │  │  │
│  │  │  - DILITHIUM3                │  │  │
│  │  └──────────┬───────────────────┘  │  │
│  └─────────────┼──────────────────────┘  │
│                │                          │
│  ┌─────────────▼──────────────────────┐  │
│  │   Luna HSM (PKCS#11)               │  │
│  │   - 개인키                         │  │
│  │   - 인증서 저장소                  │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
           │
           │ Q-TLS HTTPS
           ▼
    ┌─────────────┐
    │  클라이언트  │
    │  (Q-TLS)    │
    └─────────────┘
```

## 빌드

### 1. JAR 빌드

```bash
cd /home/user/QSIGN/Q-TLS/adapters/keycloak

# Maven으로 빌드
mvn clean package

# 출력: target/keycloak-qtls-provider-1.0.0.jar
```

### 2. Keycloak에 배포

```bash
# JAR을 Keycloak 제공자 디렉토리에 복사
sudo cp target/keycloak-qtls-provider-1.0.0.jar \
    /opt/keycloak/providers/

# Keycloak 재빌드 (Quarkus용)
cd /opt/keycloak
bin/kc.sh build

# Keycloak 재시작
sudo systemctl restart keycloak
```

## 구성

### 1. Keycloak 서버 구성

`/opt/keycloak/conf/keycloak.conf` 편집:

```properties
# Q-TLS 구성
spi-qtls-certificate-path=/opt/keycloak/conf/certs/qtls-server-cert.pem
spi-qtls-hsm-key-uri=pkcs11:token=keycloak;object=qtls-server-key;type=private
spi-qtls-hsm-pkcs11-lib=/usr/lib/libCryptoki2_64.so
spi-qtls-ca-cert-path=/opt/keycloak/conf/certs/qsign-ca-bundle.pem
spi-qtls-hybrid-mode=true
spi-qtls-mutual-tls=true
spi-qtls-fips-mode=true
spi-qtls-verify-depth=3

# HTTPS 구성
https-port=8443
https-certificate-file=/opt/keycloak/conf/certs/qtls-server-cert.pem
https-certificate-key-file=pkcs11:token=keycloak;object=qtls-server-key

# 데이터베이스
db=postgres
db-url=jdbc:postgresql://localhost:5432/keycloak
db-username=keycloak
db-password=keycloak_password

# 호스트명
hostname=auth.qsign.local
hostname-strict=true
hostname-strict-https=true

# 관리 콘솔
http-enabled=false
```

### 2. 인증서 준비

```bash
# 인증서 디렉토리 생성
sudo mkdir -p /opt/keycloak/conf/certs

# Q-TLS 인증서 복사
sudo cp /path/to/qtls-server-cert.pem /opt/keycloak/conf/certs/
sudo cp /path/to/qsign-ca-bundle.pem /opt/keycloak/conf/certs/
sudo cp /path/to/qsign-root-ca.pem /opt/keycloak/conf/certs/

# 권한 설정
sudo chown -R keycloak:keycloak /opt/keycloak/conf/certs
sudo chmod 600 /opt/keycloak/conf/certs/*.pem
```

## 테스트

### 1. Q-TLS 연결 테스트

```bash
# Q-TLS를 사용한 curl
curl --cacert /opt/keycloak/conf/certs/qsign-root-ca.pem \
     https://auth.qsign.local:8443/realms/qsign/.well-known/openid-configuration

# 예상: OpenID 구성 JSON
```

### 2. 클라이언트 인증서 인증 테스트

```bash
# 클라이언트 인증서로 인증
curl --cacert /opt/keycloak/conf/certs/qsign-root-ca.pem \
     --cert /path/to/client-cert.pem \
     --key /path/to/client-key.pem \
     https://auth.qsign.local:8443/realms/qsign/protocol/openid-connect/token \
     -d "grant_type=client_credentials" \
     -d "client_id=qtls-api-gateway" \
     -d "client_secret=<client-secret>"

# 예상: 액세스 토큰 응답
```

## 라이선스

Copyright 2025 QSIGN Project

Licensed under the Apache License, Version 2.0.

## 지원

- 이슈 트래커: https://github.com/QSIGN/Q-TLS/issues
- 문서: https://github.com/QSIGN/Q-TLS/tree/main/adapters/keycloak
- 보안 문제: security@qsign.org
