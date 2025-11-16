# Q-TLS 배포 가이드

## 목차

1. [시스템 요구사항](#시스템-요구사항)
2. [의존성 설치](#의존성-설치)
3. [Q-TLS 빌드 및 설치](#q-tls-빌드-및-설치)
4. [Kubernetes 배포](#kubernetes-배포)
5. [Docker 컨테이너화](#docker-컨테이너화)
6. [설정 파일 예제](#설정-파일-예제)
7. [보안 강화 설정](#보안-강화-설정)

---

## 시스템 요구사항

### 하드웨어 요구사항

#### 최소 요구사항 (개발/테스트 환경)

| 컴포넌트 | CPU | 메모리 | 디스크 | 네트워크 |
|---------|-----|--------|--------|---------|
| Q-TLS 서버 | 2 코어 | 4 GB | 20 GB | 100 Mbps |
| Q-TLS 클라이언트 | 1 코어 | 2 GB | 10 GB | 100 Mbps |

#### 권장 요구사항 (프로덕션 환경)

| 컴포넌트 | CPU | 메모리 | 디스크 | 네트워크 |
|---------|-----|--------|--------|---------|
| Q-TLS 서버 | 8 코어 | 16 GB | 100 GB SSD | 1 Gbps |
| Q-TLS 클라이언트 | 4 코어 | 8 GB | 50 GB SSD | 1 Gbps |
| Luna HSM | - | - | - | 1 Gbps (전용) |
| PostgreSQL | 8 코어 | 32 GB | 500 GB SSD | 1 Gbps |

#### 고가용성 구성

| 컴포넌트 | 노드 수 | CPU (총) | 메모리 (총) | 디스크 (총) |
|---------|---------|----------|-------------|-------------|
| Q-Gateway | 3+ | 24 코어 | 48 GB | 300 GB |
| Q-Sign | 2+ | 16 코어 | 64 GB | 400 GB |
| Q-KMS | 3+ | 24 코어 | 48 GB | 600 GB |
| Luna HSM | 2 (HA) | - | - | - |

### 소프트웨어 요구사항

#### 운영 체제

- **Linux** (권장):
  - Ubuntu 22.04 LTS 또는 20.04 LTS
  - RHEL 8.x 또는 9.x
  - CentOS Stream 8 또는 9
  - Debian 11 또는 12

- **기타**:
  - macOS 12.0+ (개발 환경만)
  - Windows 10/11 (WSL2 사용, 개발 환경만)

#### 필수 패키지

| 패키지 | 버전 | 용도 |
|--------|------|------|
| GCC | 9.0+ | C 컴파일러 |
| CMake | 3.16+ | 빌드 시스템 |
| OpenSSL | 1.1.1+ | 기존 암호화 |
| liboqs | 0.9.0+ | PQC 알고리즘 |
| Git | 2.25+ | 소스 관리 |
| Python | 3.8+ | 바인딩/도구 |
| Go | 1.21+ | Vault 플러그인 |
| Java | 17+ | Keycloak 프로바이더 |
| Maven | 3.8+ | Java 빌드 |
| Lua | 5.1+ | APISIX 플러그인 |

---

## 의존성 설치

### Ubuntu/Debian

```bash
#!/bin/bash
set -e

echo "=== Q-TLS 의존성 설치 (Ubuntu/Debian) ==="

# 시스템 업데이트
sudo apt-get update
sudo apt-get upgrade -y

# 빌드 도구
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    autoconf \
    automake \
    libtool \
    wget \
    curl \
    unzip

# 암호화 라이브러리
sudo apt-get install -y \
    libssl-dev \
    libssl3

# 개발 도구
sudo apt-get install -y \
    astyle \
    doxygen \
    graphviz \
    valgrind

# Python 환경
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv

# Go 설치
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Java 설치
sudo apt-get install -y openjdk-17-jdk maven

# Lua 설치
sudo apt-get install -y \
    lua5.1 \
    liblua5.1-0-dev \
    luarocks

# liboqs 설치
echo "=== liboqs 설치 ==="
cd /tmp
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake .. \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_USE_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=OFF
make -j$(nproc)
sudo make install
sudo ldconfig

# liboqs 설치 확인
pkg-config --modversion liboqs

echo "=== 의존성 설치 완료 ==="
```

### RHEL/CentOS

```bash
#!/bin/bash
set -e

echo "=== Q-TLS 의존성 설치 (RHEL/CentOS) ==="

# EPEL 저장소 활성화
sudo dnf install -y epel-release

# 빌드 도구
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y \
    cmake \
    git \
    pkgconfig \
    autoconf \
    automake \
    libtool \
    wget \
    curl \
    unzip

# 암호화 라이브러리
sudo dnf install -y \
    openssl-devel \
    openssl

# 개발 도구
sudo dnf install -y \
    astyle \
    doxygen \
    graphviz \
    valgrind

# Python 환경
sudo dnf install -y \
    python3 \
    python3-pip \
    python3-devel

# Go 설치
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Java 설치
sudo dnf install -y java-17-openjdk-devel maven

# Lua 설치
sudo dnf install -y \
    lua \
    lua-devel \
    luarocks

# liboqs 설치
echo "=== liboqs 설치 ==="
cd /tmp
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake .. \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_USE_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON
make -j$(nproc)
sudo make install
sudo ldconfig

echo "=== 의존성 설치 완료 ==="
```

### macOS

```bash
#!/bin/bash
set -e

echo "=== Q-TLS 의존성 설치 (macOS) ==="

# Homebrew 설치 (없는 경우)
if ! command -v brew &> /dev/null; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# 필수 패키지
brew install \
    cmake \
    openssl@3 \
    git \
    pkg-config \
    astyle \
    doxygen \
    python@3.11 \
    go \
    openjdk@17 \
    maven \
    lua

# liboqs 설치
brew tap open-quantum-safe/liboqs
brew install liboqs

# OpenSSL 경로 설정
echo 'export PATH="/usr/local/opt/openssl@3/bin:$PATH"' >> ~/.zshrc
echo 'export LDFLAGS="-L/usr/local/opt/openssl@3/lib"' >> ~/.zshrc
echo 'export CPPFLAGS="-I/usr/local/opt/openssl@3/include"' >> ~/.zshrc
source ~/.zshrc

echo "=== 의존성 설치 완료 ==="
```

---

## Q-TLS 빌드 및 설치

### 소스 코드 다운로드

```bash
# Git 저장소 클론
cd /home/user/QSIGN
git clone https://github.com/QSIGN/Q-TLS.git
cd Q-TLS

# 또는 릴리스 tarball 다운로드
wget https://github.com/QSIGN/Q-TLS/archive/refs/tags/v1.0.0.tar.gz
tar xzf v1.0.0.tar.gz
cd Q-TLS-1.0.0
```

### 기본 빌드

```bash
#!/bin/bash
set -e

cd /home/user/QSIGN/Q-TLS

# 빌드 디렉토리 생성
mkdir -p build
cd build

# CMake 구성 (기본 옵션)
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DENABLE_TESTS=ON \
    -DENABLE_EXAMPLES=ON

# 빌드
make -j$(nproc)

# 테스트 실행
make test

# 설치
sudo make install

# 라이브러리 캐시 업데이트
sudo ldconfig

# 설치 확인
ldconfig -p | grep libqtls
pkg-config --modversion qtls
```

### HSM 지원 빌드

```bash
#!/bin/bash
set -e

cd /home/user/QSIGN/Q-TLS

# Luna HSM 클라이언트 설치 확인
if [ ! -f /usr/lib/libCryptoki2_64.so ]; then
    echo "ERROR: Luna HSM 클라이언트가 설치되지 않았습니다."
    echo "Luna HSM 클라이언트를 먼저 설치하세요."
    exit 1
fi

mkdir -p build-hsm
cd build-hsm

# CMake 구성 (HSM 지원)
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DENABLE_HSM=ON \
    -DHSM_PKCS11_LIB=/usr/lib/libCryptoki2_64.so \
    -DENABLE_TESTS=ON \
    -DENABLE_EXAMPLES=ON

# 빌드
make -j$(nproc)

# HSM 연결 테스트
/usr/safenet/lunaclient/bin/vtl verify

# 테스트 실행
make test

# 설치
sudo make install
sudo ldconfig
```

### FIPS 모드 빌드

```bash
#!/bin/bash
set -e

cd /home/user/QSIGN/Q-TLS

mkdir -p build-fips
cd build-fips

# CMake 구성 (FIPS 모드)
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DENABLE_HSM=ON \
    -DFIPS_MODE=ON \
    -DENABLE_TESTS=ON

# 빌드
make -j$(nproc)

# FIPS 자체 테스트
make fips-test

# 설치
sudo make install
sudo ldconfig

# FIPS 모드 확인
qtls-version --fips
```

### 빌드 옵션

| CMake 옵션 | 기본값 | 설명 |
|-----------|--------|------|
| `CMAKE_BUILD_TYPE` | Release | 빌드 타입 (Debug/Release/RelWithDebInfo) |
| `CMAKE_INSTALL_PREFIX` | /usr/local | 설치 경로 |
| `ENABLE_HSM` | OFF | Luna HSM 지원 활성화 |
| `HSM_PKCS11_LIB` | /usr/lib/libCryptoki2_64.so | PKCS#11 라이브러리 경로 |
| `FIPS_MODE` | OFF | FIPS 140-2 준수 모드 |
| `ENABLE_TESTS` | ON | 테스트 스위트 빌드 |
| `ENABLE_EXAMPLES` | ON | 예제 프로그램 빌드 |
| `ENABLE_LOGGING` | ON | 상세 로깅 활성화 |
| `ENABLE_PYTHON_BINDING` | ON | Python 바인딩 빌드 |
| `ENABLE_GO_BINDING` | ON | Go 바인딩 빌드 |
| `ENABLE_NODEJS_BINDING` | ON | Node.js 바인딩 빌드 |
| `BUILD_SHARED_LIBS` | ON | 공유 라이브러리 빌드 |
| `BUILD_STATIC_LIBS` | OFF | 정적 라이브러리 빌드 |

### 바인딩 빌드

#### Python 바인딩

```bash
cd /home/user/QSIGN/Q-TLS/bindings/python

# 가상 환경 생성
python3 -m venv venv
source venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# 빌드 및 설치
python setup.py build
python setup.py install

# 테스트
python -c "import qtls; print(qtls.version())"
```

#### Node.js 바인딩

```bash
cd /home/user/QSIGN/Q-TLS/bindings/nodejs

# 의존성 설치
npm install

# 빌드
npm run build

# 테스트
npm test

# 전역 설치
npm install -g .
```

#### Go 바인딩

```bash
cd /home/user/QSIGN/Q-TLS/bindings/go

# 모듈 초기화
go mod init github.com/QSIGN/Q-TLS/bindings/go

# 의존성 다운로드
go mod download

# 빌드
go build -o qtls-go

# 테스트
go test -v ./...

# 설치
go install
```

---

## Kubernetes 배포

### 사전 준비

```bash
# Kubernetes 클러스터 확인
kubectl version
kubectl cluster-info

# Namespace 생성
kubectl create namespace qsign

# Secret 생성 (인증서)
kubectl create secret generic qsign-certs \
    --from-file=server-cert=/etc/qsign/ca/certs/server-cert.pem \
    --from-file=server-key=/etc/qsign/ca/certs/server-key.pem \
    --from-file=ca-bundle=/etc/qsign/ca/certs/qsign-ca-bundle.pem \
    -n qsign

# ConfigMap 생성
kubectl create configmap qtls-config \
    --from-file=/home/user/QSIGN/Q-TLS/configs/ \
    -n qsign
```

### Q-TLS 서버 배포

```yaml
# qtls-server-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qtls-server
  namespace: qsign
  labels:
    app: qtls-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: qtls-server
  template:
    metadata:
      labels:
        app: qtls-server
    spec:
      containers:
      - name: qtls-server
        image: qsign/qtls-server:1.0.0
        ports:
        - containerPort: 8443
          name: qtls
          protocol: TCP
        env:
        - name: QTLS_SERVER_PORT
          value: "8443"
        - name: QTLS_HYBRID_MODE
          value: "true"
        - name: QTLS_FIPS_MODE
          value: "true"
        - name: QTLS_LOG_LEVEL
          value: "info"
        volumeMounts:
        - name: certs
          mountPath: /etc/qtls/certs
          readOnly: true
        - name: config
          mountPath: /etc/qtls/config
          readOnly: true
        - name: hsm-client
          mountPath: /usr/safenet/lunaclient
          readOnly: true
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          tcpSocket:
            port: 8443
          initialDelaySeconds: 15
          periodSeconds: 20
        readinessProbe:
          tcpSocket:
            port: 8443
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: certs
        secret:
          secretName: qsign-certs
      - name: config
        configMap:
          name: qtls-config
      - name: hsm-client
        hostPath:
          path: /usr/safenet/lunaclient
          type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: qtls-server
  namespace: qsign
spec:
  type: LoadBalancer
  selector:
    app: qtls-server
  ports:
  - port: 8443
    targetPort: 8443
    protocol: TCP
    name: qtls
  sessionAffinity: ClientIP
```

### 배포 및 확인

```bash
# 배포
kubectl apply -f qtls-server-deployment.yaml

# 상태 확인
kubectl get deployments -n qsign
kubectl get pods -n qsign
kubectl get services -n qsign

# 로그 확인
kubectl logs -f deployment/qtls-server -n qsign

# 서비스 테스트
EXTERNAL_IP=$(kubectl get svc qtls-server -n qsign -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
openssl s_client -connect $EXTERNAL_IP:8443 -showcerts
```

### Horizontal Pod Autoscaler

```yaml
# qtls-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: qtls-server-hpa
  namespace: qsign
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: qtls-server
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
```

---

## Docker 컨테이너화

### Dockerfile

```dockerfile
# Dockerfile
FROM ubuntu:22.04 AS builder

# 빌드 의존성 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config \
    wget \
    && rm -rf /var/lib/apt/lists/*

# liboqs 설치
WORKDIR /tmp
RUN git clone https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_USE_OPENSSL=ON \
        -DBUILD_SHARED_LIBS=ON && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Q-TLS 소스 복사
WORKDIR /build
COPY . .

# Q-TLS 빌드
RUN mkdir build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DENABLE_HSM=OFF \
        -DENABLE_TESTS=OFF \
        -DENABLE_EXAMPLES=ON && \
    make -j$(nproc) && \
    make install

# 런타임 이미지
FROM ubuntu:22.04

# 런타임 의존성 설치
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# liboqs 복사
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Q-TLS 복사
COPY --from=builder /usr/local/lib/libqtls.so* /usr/local/lib/
COPY --from=builder /usr/local/include/qtls /usr/local/include/qtls
COPY --from=builder /usr/local/bin/qtls-* /usr/local/bin/

# 예제 서버 복사
COPY --from=builder /build/build/examples/simple_server /usr/local/bin/

# 라이브러리 캐시 업데이트
RUN ldconfig

# 사용자 생성
RUN useradd -r -s /bin/false qtls

# 포트 노출
EXPOSE 8443

# 작업 디렉토리
WORKDIR /app

# 비-루트 사용자로 실행
USER qtls

# 헬스체크
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD timeout 2 bash -c "</dev/tcp/localhost/8443" || exit 1

# 서버 시작
CMD ["/usr/local/bin/simple_server"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  qtls-server:
    build:
      context: .
      dockerfile: Dockerfile
    image: qsign/qtls-server:1.0.0
    container_name: qtls-server
    restart: unless-stopped
    ports:
      - "8443:8443"
    volumes:
      - ./certs:/etc/qtls/certs:ro
      - ./config:/etc/qtls/config:ro
      - qtls-data:/var/lib/qtls
    environment:
      - QTLS_SERVER_PORT=8443
      - QTLS_HYBRID_MODE=true
      - QTLS_LOG_LEVEL=info
    networks:
      - qsign-network
    healthcheck:
      test: ["CMD", "timeout", "2", "bash", "-c", "</dev/tcp/localhost/8443"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  qtls-client:
    build:
      context: .
      dockerfile: Dockerfile.client
    image: qsign/qtls-client:1.0.0
    container_name: qtls-client
    depends_on:
      qtls-server:
        condition: service_healthy
    volumes:
      - ./certs:/etc/qtls/certs:ro
    environment:
      - QTLS_SERVER_HOST=qtls-server
      - QTLS_SERVER_PORT=8443
      - QTLS_HYBRID_MODE=true
    networks:
      - qsign-network
    command: /usr/local/bin/simple_client qtls-server 8443

networks:
  qsign-network:
    driver: bridge

volumes:
  qtls-data:
    driver: local
```

### 빌드 및 실행

```bash
# Docker 이미지 빌드
docker build -t qsign/qtls-server:1.0.0 .

# 컨테이너 실행
docker run -d \
    --name qtls-server \
    -p 8443:8443 \
    -v $(pwd)/certs:/etc/qtls/certs:ro \
    -e QTLS_HYBRID_MODE=true \
    qsign/qtls-server:1.0.0

# 로그 확인
docker logs -f qtls-server

# 컨테이너 접속
docker exec -it qtls-server /bin/bash

# Docker Compose 사용
docker-compose up -d
docker-compose ps
docker-compose logs -f

# 정리
docker-compose down
docker rmi qsign/qtls-server:1.0.0
```

### 멀티 아키텍처 빌드

```bash
# Buildx 설정
docker buildx create --name qsign-builder --use
docker buildx inspect --bootstrap

# 멀티 아키텍처 빌드
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -t qsign/qtls-server:1.0.0 \
    --push \
    .

# 확인
docker buildx imagetools inspect qsign/qtls-server:1.0.0
```

---

## 설정 파일 예제

### 서버 구성 파일

```json
// /etc/qtls/config/server.json
{
  "server": {
    "listen_address": "0.0.0.0",
    "listen_port": 8443,
    "worker_threads": 4,
    "max_connections": 10000
  },
  "tls": {
    "protocol_version": "1.3",
    "hybrid_mode": true,
    "pqc_only": false,
    "session_timeout": 3600,
    "session_cache_size": 10000
  },
  "certificates": {
    "server_cert": "/etc/qtls/certs/server-cert.pem",
    "server_key_uri": "pkcs11:token=qtls-server;object=server-key;type=private",
    "ca_bundle": "/etc/qtls/certs/ca-bundle.pem",
    "verify_client": true,
    "verify_depth": 3
  },
  "hsm": {
    "enabled": true,
    "pkcs11_library": "/usr/lib/libCryptoki2_64.so",
    "token_label": "qtls-server",
    "pin": "${QTLS_HSM_PIN}",
    "session_pool_size": 10
  },
  "algorithms": {
    "kem": ["kyber1024", "ecdhe-p384"],
    "signature": ["dilithium3", "rsa-4096"],
    "cipher": ["aes-256-gcm", "chacha20-poly1305"]
  },
  "logging": {
    "level": "info",
    "file": "/var/log/qtls/server.log",
    "max_size_mb": 100,
    "max_files": 10,
    "console": true
  },
  "metrics": {
    "enabled": true,
    "port": 9091,
    "path": "/metrics"
  },
  "fips": {
    "enabled": true,
    "self_test_on_load": true
  }
}
```

### 클라이언트 구성 파일

```json
// /etc/qtls/config/client.json
{
  "client": {
    "connect_timeout": 30,
    "read_timeout": 60,
    "write_timeout": 60,
    "max_retries": 3
  },
  "tls": {
    "protocol_version": "1.3",
    "hybrid_mode": true,
    "server_name_indication": true,
    "verify_peer": true
  },
  "certificates": {
    "client_cert": "/etc/qtls/certs/client-cert.pem",
    "client_key": "/etc/qtls/certs/client-key.pem",
    "ca_bundle": "/etc/qtls/certs/ca-bundle.pem"
  },
  "algorithms": {
    "kem": ["kyber1024", "ecdhe-p384"],
    "signature": ["dilithium3", "rsa-4096"],
    "cipher": ["aes-256-gcm"]
  },
  "logging": {
    "level": "warn",
    "file": "/var/log/qtls/client.log",
    "console": false
  }
}
```

### systemd 서비스 파일

```ini
# /etc/systemd/system/qtls-server.service
[Unit]
Description=Q-TLS Server
Documentation=https://github.com/QSIGN/Q-TLS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=qtls
Group=qtls
WorkingDirectory=/var/lib/qtls

ExecStartPre=/usr/local/bin/qtls-server --test-config
ExecStart=/usr/local/bin/qtls-server --config /etc/qtls/config/server.json
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# 보안 설정
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/qtls /var/log/qtls

# 리소스 제한
LimitNOFILE=65536
LimitNPROC=4096

# 환경 변수
Environment="QTLS_HSM_PIN_FILE=/etc/qtls/secrets/hsm-pin"
EnvironmentFile=-/etc/qtls/environment

[Install]
WantedBy=multi-user.target
```

### 로그 로테이션

```
# /etc/logrotate.d/qtls
/var/log/qtls/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 qtls qtls
    sharedscripts
    postrotate
        systemctl reload qtls-server > /dev/null 2>&1 || true
    endscript
}
```

---

## 보안 강화 설정

### 파일 시스템 보안

```bash
# Q-TLS 사용자 및 그룹 생성
sudo groupadd -r qtls
sudo useradd -r -g qtls -s /bin/false -d /var/lib/qtls qtls

# 디렉토리 생성 및 권한 설정
sudo mkdir -p /etc/qtls/{config,certs,secrets}
sudo mkdir -p /var/lib/qtls
sudo mkdir -p /var/log/qtls

# 소유권 설정
sudo chown -R qtls:qtls /var/lib/qtls
sudo chown -R qtls:qtls /var/log/qtls
sudo chown -R root:qtls /etc/qtls

# 권한 설정
sudo chmod 750 /etc/qtls/config
sudo chmod 700 /etc/qtls/secrets
sudo chmod 750 /etc/qtls/certs
sudo chmod 750 /var/lib/qtls
sudo chmod 750 /var/log/qtls

# 인증서 및 키 권한
sudo chmod 640 /etc/qtls/certs/*.pem
sudo chmod 600 /etc/qtls/secrets/*
```

### SELinux 정책

```bash
# SELinux 컨텍스트 설정 (RHEL/CentOS)
sudo semanage fcontext -a -t bin_t "/usr/local/bin/qtls-.*"
sudo semanage fcontext -a -t etc_t "/etc/qtls(/.*)?"
sudo semanage fcontext -a -t var_lib_t "/var/lib/qtls(/.*)?"
sudo semanage fcontext -a -t var_log_t "/var/log/qtls(/.*)?"

# 컨텍스트 적용
sudo restorecon -Rv /usr/local/bin/qtls-*
sudo restorecon -Rv /etc/qtls
sudo restorecon -Rv /var/lib/qtls
sudo restorecon -Rv /var/log/qtls

# SELinux 정책 생성
sudo tee /etc/selinux/qtls.te > /dev/null <<'EOF'
module qtls 1.0;

require {
    type init_t;
    type qtls_t;
    type qtls_exec_t;
    type qtls_var_lib_t;
    type qtls_var_log_t;
    class file { read write create open };
    class tcp_socket { bind listen accept };
}

# Q-TLS 프로세스 도메인
type qtls_t;
type qtls_exec_t;
init_daemon_domain(qtls_t, qtls_exec_t)

# 데이터 디렉토리
type qtls_var_lib_t;
files_type(qtls_var_lib_t)

# 로그 디렉토리
type qtls_var_log_t;
logging_log_file(qtls_var_log_t)

# 권한 부여
allow qtls_t qtls_var_lib_t:file { read write create open };
allow qtls_t qtls_var_log_t:file { read write create open };
allow qtls_t self:tcp_socket { bind listen accept };
EOF

# 정책 컴파일 및 로드
sudo checkmodule -M -m -o /tmp/qtls.mod /etc/selinux/qtls.te
sudo semodule_package -o /tmp/qtls.pp -m /tmp/qtls.mod
sudo semodule -i /tmp/qtls.pp
```

### AppArmor 프로파일

```bash
# AppArmor 프로파일 생성 (Ubuntu/Debian)
sudo tee /etc/apparmor.d/usr.local.bin.qtls-server > /dev/null <<'EOF'
#include <tunables/global>

/usr/local/bin/qtls-server {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # 실행 권한
  /usr/local/bin/qtls-server mr,

  # 라이브러리
  /usr/local/lib/libqtls.so* mr,
  /usr/local/lib/liboqs.so* mr,
  /usr/lib/x86_64-linux-gnu/libssl.so* mr,
  /usr/lib/x86_64-linux-gnu/libcrypto.so* mr,

  # 설정 파일
  /etc/qtls/config/** r,
  /etc/qtls/certs/** r,
  /etc/qtls/secrets/** r,

  # 데이터 디렉토리
  /var/lib/qtls/** rw,

  # 로그 디렉토리
  /var/log/qtls/** rw,

  # HSM 라이브러리
  /usr/lib/libCryptoki2_64.so mr,
  /usr/safenet/lunaclient/** r,

  # 네트워크
  network inet stream,
  network inet6 stream,

  # 프로세스
  capability setuid,
  capability setgid,
  capability net_bind_service,
}
EOF

# 프로파일 로드
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.qtls-server

# 프로파일 활성화
sudo aa-enforce /usr/local/bin/qtls-server
```

### 방화벽 설정

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 8443/tcp comment 'Q-TLS Server'
sudo ufw allow 9091/tcp comment 'Q-TLS Metrics'
sudo ufw enable

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=9091/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9091 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### 네트워크 보안

```bash
# sysctl 보안 설정
sudo tee /etc/sysctl.d/99-qtls.conf > /dev/null <<'EOF'
# TCP 보안
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# IP 스푸핑 방지
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ICMP 리다이렉트 비활성화
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# IP 포워딩 비활성화
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 성능 튜닝
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF

sudo sysctl -p /etc/sysctl.d/99-qtls.conf
```

### 감사 로깅

```bash
# auditd 규칙 설정
sudo tee /etc/audit/rules.d/qtls.rules > /dev/null <<'EOF'
# Q-TLS 실행 파일 감사
-w /usr/local/bin/qtls-server -p x -k qtls-exec

# 설정 파일 감사
-w /etc/qtls/config/ -p wa -k qtls-config
-w /etc/qtls/certs/ -p wa -k qtls-certs
-w /etc/qtls/secrets/ -p rwa -k qtls-secrets

# HSM 접근 감사
-w /usr/lib/libCryptoki2_64.so -p x -k qtls-hsm

# 시스템 호출 감사
-a always,exit -F arch=b64 -S socket -F a0=2 -F a1=1 -k qtls-network
-a always,exit -F arch=b64 -S connect -k qtls-network
-a always,exit -F arch=b64 -S bind -k qtls-network
EOF

# auditd 재시작
sudo service auditd restart

# 감사 로그 확인
sudo ausearch -k qtls-exec
```

---

## 부록

### A. 체크리스트

#### 배포 전 체크리스트

- [ ] 시스템 요구사항 확인
- [ ] 모든 의존성 설치 완료
- [ ] Q-TLS 빌드 및 테스트 성공
- [ ] Luna HSM 연결 및 키 생성 완료
- [ ] 인증서 발급 및 검증 완료
- [ ] 방화벽 및 네트워크 구성 완료
- [ ] 보안 강화 설정 적용
- [ ] 모니터링 및 로깅 구성 완료
- [ ] 백업 및 복구 계획 수립
- [ ] 문서화 완료

#### 배포 후 체크리스트

- [ ] 서비스 정상 동작 확인
- [ ] TLS 핸드셰이크 성공 확인
- [ ] HSM 작업 정상 동작 확인
- [ ] 인증서 검증 성공 확인
- [ ] 로그 및 메트릭 수집 확인
- [ ] 알림 시스템 테스트
- [ ] 성능 벤치마크 수행
- [ ] 보안 취약점 스캔
- [ ] 장애 복구 테스트
- [ ] 운영 절차 문서화

### B. 문제 해결 팁

```bash
# 빌드 실패 시
rm -rf build/
mkdir build && cd build
cmake .. -DCMAKE_VERBOSE_MAKEFILE=ON
make VERBOSE=1

# 라이브러리 로딩 오류 시
ldconfig -p | grep qtls
ldd /usr/local/bin/qtls-server
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# HSM 연결 오류 시
/usr/safenet/lunaclient/bin/vtl verify
/usr/safenet/lunaclient/bin/vtl assignPartition -list
export PKCS11_MODULE=/usr/lib/libCryptoki2_64.so

# 권한 오류 시
sudo chown -R qtls:qtls /var/lib/qtls /var/log/qtls
sudo chmod 750 /etc/qtls/*
```

### C. 참고 자료

- [QSIGN 통합 가이드](/home/user/QSIGN/Q-TLS/docs/QSIGN-INTEGRATION.md)
- [Q-TLS API 레퍼런스](/home/user/QSIGN/Q-TLS/docs/API-REFERENCE.md)
- [Q-TLS 보안 가이드](/home/user/QSIGN/Q-TLS/docs/SECURITY.md)
- [Q-TLS 성능 가이드](/home/user/QSIGN/Q-TLS/docs/PERFORMANCE.md)

---

**문서 버전**: 1.0.0
**최종 업데이트**: 2025년 1월 16일
**작성자**: QSIGN Project Team
