# Apache APISIX용 Q-TLS 플러그인

## 개요

Q-TLS 플러그인은 Apache APISIX API 게이트웨이에 양자 내성 암호화를 통합하여 API 트래픽에 대한 하이브리드 양자 후 보호를 제공합니다. 이 플러그인을 사용하면 APISIX가 키 교환에 KYBER1024를, 디지털 서명에 DILITHIUM3을 사용할 수 있으며, 심층 방어 보안을 위해 기존 알고리즘과 결합됩니다.

## 기능

- **하이브리드 암호화**: ECDHE P-384 + KYBER1024 키 교환, RSA/ECDSA + DILITHIUM3 서명
- **Luna HSM 통합**: PKCS#11을 통한 안전한 키 저장소
- **상호 TLS 지원**: QSIGN PKI를 사용한 클라이언트 인증서 검증
- **세션 관리**: 효율적인 세션 캐싱 및 재개
- **FIPS 140-2 모드**: 준수 암호화 작업
- **Prometheus 메트릭**: 포괄적인 모니터링 및 관찰 가능성
- **속도 제한**: 핸드셰이크 플러딩 방지
- **상태 검사**: HSM 및 연결 자동 모니터링

## 아키텍처

```
┌─────────────┐
│   클라이언트  │
│  (Q-TLS)    │
└──────┬──────┘
       │ KYBER1024 + ECDHE
       │ DILITHIUM3 + RSA
       ▼
┌─────────────────────────────────┐
│     Apache APISIX 게이트웨이     │
│  ┌─────────────────────────┐   │
│  │   Q-TLS 플러그인 (Lua)   │   │
│  │  ┌──────────────────┐   │   │
│  │  │ FFI → libqtls.so │   │   │
│  │  └────────┬─────────┘   │   │
│  └───────────┼─────────────┘   │
│              │                  │
│  ┌───────────▼─────────────┐   │
│  │   Luna HSM (PKCS#11)    │   │
│  │  - DILITHIUM3 키        │   │
│  │  - KYBER1024 임시 키    │   │
│  └─────────────────────────┘   │
└──────────┬──────────────────────┘
           │ Q-TLS 또는 HTTPS
           ▼
    ┌──────────────┐
    │   업스트림    │
    │   서비스      │
    └──────────────┘
```

## 설치

### 1. 플러그인 파일 복사

```bash
# 플러그인을 APISIX 플러그인 디렉토리에 복사
sudo cp qtls-plugin.lua /usr/local/apisix/apisix/plugins/qtls.lua
sudo cp schema.lua /usr/local/apisix/apisix/plugins/qtls/schema.lua

# 권한 설정
sudo chmod 644 /usr/local/apisix/apisix/plugins/qtls.lua
sudo chmod 644 /usr/local/apisix/apisix/plugins/qtls/schema.lua
```

### 2. 플러그인 활성화

`/usr/local/apisix/conf/config.yaml` 편집:

```yaml
plugins:
  - qtls  # 플러그인 목록에 추가

plugin_attr:
  qtls:
    hsm_pkcs11_lib: /usr/lib/libCryptoki2_64.so
    hybrid_mode: true
    log_level: info
```

### 3. 인증서 구성

```bash
# SSL 디렉토리 생성
sudo mkdir -p /etc/apisix/ssl

# Q-TLS 하이브리드 인증서 복사
sudo cp /path/to/qtls-server-cert.pem /etc/apisix/ssl/
sudo cp /path/to/qsign-ca-bundle.pem /etc/apisix/ssl/
sudo cp /path/to/qsign-root-ca.pem /etc/apisix/ssl/

# 권한 설정
sudo chmod 600 /etc/apisix/ssl/*.pem
```

### 4. APISIX 시작

```bash
# APISIX 시작
sudo apisix start

# 로그 확인
tail -f /usr/local/apisix/logs/error.log

# Q-TLS 플러그인이 로드되었는지 확인
curl http://127.0.0.1:9180/apisix/admin/plugins/qtls \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1'
```

## 구성

### 기본 라우트 구성

```bash
# Q-TLS 보호가 있는 라우트 생성
curl http://127.0.0.1:9180/apisix/admin/routes/1 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -X PUT -d '
{
  "uri": "/api/*",
  "plugins": {
    "qtls": {
      "certificate": "/etc/apisix/ssl/qtls-server-cert.pem",
      "hsm_key_uri": "pkcs11:token=qtls-apisix;object=qtls-server-key",
      "hybrid_mode": true,
      "require_qtls": true
    }
  },
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "backend.example.com:8443": 1
    }
  }
}'
```

### 상호 TLS 구성

```bash
# 상호 TLS가 있는 라우트 생성
curl http://127.0.0.1:9180/apisix/admin/routes/2 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -X PUT -d '
{
  "uri": "/admin/*",
  "plugins": {
    "qtls": {
      "certificate": "/etc/apisix/ssl/qtls-server-cert.pem",
      "hsm_key_uri": "pkcs11:token=qtls-apisix;object=qtls-admin-key",
      "hybrid_mode": true,
      "mutual_tls": true,
      "client_ca_cert": "/etc/apisix/ssl/qsign-ca-bundle.pem",
      "verify_depth": 3,
      "require_qtls": true
    }
  },
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "admin.example.com:8443": 1
    }
  }
}'
```

## 구성 옵션

| 매개변수 | 타입 | 기본값 | 설명 |
|-----------|------|---------|-------------|
| `certificate` | string | 필수 | Q-TLS 하이브리드 인증서 경로 |
| `hsm_key_uri` | string | 선택 | HSM 키용 PKCS#11 URI |
| `hybrid_mode` | boolean | true | PQC 하이브리드 모드 활성화 |
| `mutual_tls` | boolean | false | 클라이언트 인증서 검증 활성화 |
| `require_qtls` | boolean | false | 비 Q-TLS 연결 거부 |
| `session_timeout` | integer | 3600 | 세션 타임아웃 (초) |
| `fips_mode` | boolean | false | FIPS 140-2 모드 활성화 |
| `enable_metrics` | boolean | true | Prometheus 메트릭 활성화 |

## 라이선스

Copyright 2025 QSIGN Project

Licensed under the Apache License, Version 2.0.

## 지원

- 이슈 트래커: https://github.com/QSIGN/Q-TLS/issues
- 문서: https://github.com/QSIGN/Q-TLS/tree/main/adapters/apisix
- 보안 문제: security@qsign.org
