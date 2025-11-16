# HashiCorp Vault용 Q-TLS 시크릿 엔진

## 개요

Q-TLS 시크릿 엔진은 HashiCorp Vault에 양자 내성 암호화 작업을 제공하여 조직이 양자 후 시대를 준비할 수 있도록 합니다. 이 플러그인은 키 캡슐화를 위한 KYBER1024와 디지털 서명을 위한 DILITHIUM3을 통합하며, 안전한 키 저장을 위한 Luna HSM 지원을 제공합니다.

## 기능

- **양자 내성 암호화**: KYBER1024 KEM 및 DILITHIUM3 서명
- **하이브리드 모드**: 심층 방어를 위한 기존 및 PQC 알고리즘 결합
- **Luna HSM 통합**: PKCS#11을 통한 FIPS 140-2 Level 3 준수 키 저장소
- **QSIGN PKI 지원**: 인증서 생성 및 관리
- **키 관리**: 양자 내성 키 생성, 저장, 순환 및 삭제
- **암호화 작업**: 캡슐화, 역캡슐화, 서명, 검증
- **엔터프라이즈 준비**: 프로덕션 등급 오류 처리, 로깅 및 메트릭
- **API 우선 설계**: 쉬운 통합을 위한 RESTful API

## 아키텍처

```
┌─────────────────────────────────────────┐
│         HashiCorp Vault                 │
│  ┌────────────────────────────────────┐ │
│  │   Q-TLS 시크릿 엔진                 │ │
│  │                                    │ │
│  │  ┌──────────────────────────────┐ │ │
│  │  │  백엔드 (Go)                  │ │ │
│  │  │  - 키 관리                   │ │ │
│  │  │  - 암호화 작업               │ │ │
│  │  │  - 인증서 처리               │ │ │
│  │  └────────┬─────────────────────┘ │ │
│  │           │                        │ │
│  │  ┌────────▼─────────────────────┐ │ │
│  │  │  HSM 풀 (CGO/PKCS#11)        │ │ │
│  │  │  - 세션 관리                 │ │ │
│  │  │  - 키 생성                   │ │ │
│  │  │  - 암호화 작업               │ │ │
│  │  └────────┬─────────────────────┘ │ │
│  └───────────┼────────────────────────┘ │
│              │                           │
│  ┌───────────▼──────────────────────┐   │
│  │   Luna HSM (PKCS#11)             │   │
│  │   - KYBER1024 키                 │   │
│  │   - DILITHIUM3 키                │   │
│  │   - FIPS 140-2 Level 3           │   │
│  └──────────────────────────────────┘   │
└──────────────────────────────────────────┘
           │
           │ Vault API
           ▼
    ┌─────────────┐
    │  클라이언트  │
    └─────────────┘
```

## 빌드

### 1. 플러그인 바이너리 빌드

```bash
cd /home/user/QSIGN/Q-TLS/adapters/vault

# 의존성 다운로드
go mod download

# 플러그인 빌드
go build -o vault-plugin-secrets-qtls main.go

# 빌드 확인
./vault-plugin-secrets-qtls --version
```

### 2. 플러그인 SHA256 계산

```bash
# Vault 플러그인 등록을 위한 체크섬 계산
sha256sum vault-plugin-secrets-qtls > SHA256SUMS
```

### 3. Vault 플러그인 디렉토리에 복사

```bash
# 플러그인 디렉토리 생성
sudo mkdir -p /etc/vault/plugins

# 플러그인 복사
sudo cp vault-plugin-secrets-qtls /etc/vault/plugins/
sudo chmod +x /etc/vault/plugins/vault-plugin-secrets-qtls
```

## 설치

### 1. Vault 구성

`/etc/vault/config.hcl` 편집:

```hcl
# Vault 구성
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/etc/vault/tls/vault-cert.pem"
  tls_key_file  = "/etc/vault/tls/vault-key.pem"
}

# 플러그인 디렉토리
plugin_directory = "/etc/vault/plugins"

# API 주소
api_addr = "https://vault.qsign.local:8200"
cluster_addr = "https://vault.qsign.local:8201"

# UI 활성화
ui = true
```

### 2. Q-TLS 플러그인 등록

```bash
# 플러그인 SHA256 가져오기
PLUGIN_SHA=$(sha256sum /etc/vault/plugins/vault-plugin-secrets-qtls | cut -d' ' -f1)

# 플러그인 등록
vault plugin register \
  -sha256=$PLUGIN_SHA \
  secret \
  vault-plugin-secrets-qtls

# 등록 확인
vault plugin list secret
```

### 3. Q-TLS 시크릿 엔진 활성화

```bash
# 기본 경로에서 활성화
vault secrets enable \
  -path=qtls \
  -plugin-name=vault-plugin-secrets-qtls \
  plugin

# 확인
vault secrets list
```

## 사용법

### 키 관리

#### KYBER1024 키 생성

```bash
# HSM에서 키 생성
vault write qtls/keys/my-kyber-key \
  type=kyber1024 \
  use_hsm=true \
  metadata='{\"purpose\": \"key exchange\"}'

# 응답:
# Key           Value
# ---           -----
# name          my-kyber-key
# type          kyber1024
# public_key    <base64-encoded-public-key>
# created_at    2025-01-16T10:30:00Z
# use_hsm       true
```

#### DILITHIUM3 키 생성

```bash
# 서명 키 생성
vault write qtls/keys/my-dilithium-key \
  type=dilithium3 \
  use_hsm=true \
  metadata='{\"purpose\": \"digital signature\"}'
```

### 암호화 작업

#### KYBER 캡슐화

```bash
# 공유 비밀 생성을 위한 캡슐화
vault write qtls/encapsulate/my-kyber-key

# 응답:
# Key              Value
# ---              -----
# ciphertext       <base64-encoded-ciphertext>
# shared_secret    <base64-encoded-shared-secret>
# algorithm        KYBER1024
```

#### KYBER 역캡슐화

```bash
# 공유 비밀 복구를 위한 역캡슐화
vault write qtls/decapsulate/my-kyber-key \
  ciphertext="<base64-encoded-ciphertext>"

# 응답:
# Key              Value
# ---              -----
# shared_secret    <base64-encoded-shared-secret>
# algorithm        KYBER1024
```

#### DILITHIUM 서명

```bash
# 메시지 서명
MESSAGE=$(echo -n "안녕하세요, 양자 세계!" | base64)

vault write qtls/sign/my-dilithium-key \
  message="$MESSAGE"

# 응답:
# Key          Value
# ---          -----
# signature    <base64-encoded-signature>
# algorithm    DILITHIUM3
```

#### DILITHIUM 검증

```bash
# 서명 검증
vault write qtls/verify/my-dilithium-key \
  message="$MESSAGE" \
  signature="<base64-encoded-signature>"

# 응답:
# Key          Value
# ---          -----
# valid        true
# algorithm    DILITHIUM3
```

## 라이선스

Copyright 2025 QSIGN Project

Licensed under the Apache License, Version 2.0.

## 지원

- 이슈 트래커: https://github.com/QSIGN/Q-TLS/issues
- 문서: https://github.com/QSIGN/Q-TLS/tree/main/adapters/vault
- 보안 문제: security@qsign.org

## 참고 자료

- HashiCorp Vault: https://www.vaultproject.io/
- Vault 플러그인 개발: https://www.vaultproject.io/docs/plugin
- Q-TLS 프로젝트: https://github.com/QSIGN/Q-TLS
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
