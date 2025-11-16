#!/bin/bash
#
# Q-TLS Mutual TLS 인증서 생성 스크립트
#
# 이 스크립트는 상호 TLS 인증을 위한 다음 인증서들을 생성합니다:
# 1. CA (Certificate Authority) 인증서
# 2. 서버 인증서 (CA로 서명)
# 3. 클라이언트 인증서 (CA로 서명)
#

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo " Q-TLS 상호 TLS 인증서 생성"
echo "=================================================="
echo ""

# 인증서 디렉토리 생성
CERT_DIR="certs"
if [ -d "$CERT_DIR" ]; then
    echo -e "${YELLOW}[WARN] 기존 인증서 디렉토리가 존재합니다.${NC}"
    read -p "덮어쓰시겠습니까? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "취소되었습니다."
        exit 0
    fi
    rm -rf "$CERT_DIR"
fi

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# 설정 변수
DAYS=365
COUNTRY="KR"
STATE="Seoul"
LOCALITY="Seoul"
ORGANIZATION="QSIGN Project"

# ============================================================
# 1. CA (Certificate Authority) 생성
# ============================================================
echo -e "${GREEN}[1/6] CA 개인키 생성 중...${NC}"
openssl genrsa -out ca.key 4096

echo -e "${GREEN}[2/6] CA 인증서 생성 중...${NC}"
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=Certificate Authority/CN=QSIGN Root CA"

echo -e "${GREEN}[INFO] CA 인증서 생성 완료${NC}"
openssl x509 -in ca.crt -noout -subject -dates

# ============================================================
# 2. 서버 인증서 생성
# ============================================================
echo ""
echo -e "${GREEN}[3/6] 서버 개인키 생성 중...${NC}"
openssl genrsa -out server.key 4096

echo -e "${GREEN}[4/6] 서버 CSR 생성 중...${NC}"
openssl req -new -key server.key -out server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=Q-TLS Server/CN=localhost"

echo -e "${GREEN}[5/6] 서버 인증서 서명 중 (CA로 서명)...${NC}"
# SAN (Subject Alternative Name) 설정 - localhost 및 IP 주소 지원
cat > server_ext.cnf << EOF
subjectAltName = DNS:localhost,DNS:*.localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -days $DAYS -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -extfile server_ext.cnf

rm server_ext.cnf

echo -e "${GREEN}[INFO] 서버 인증서 생성 완료${NC}"
openssl x509 -in server.crt -noout -subject -issuer -dates

# ============================================================
# 3. 클라이언트 인증서 생성
# ============================================================
echo ""
echo -e "${GREEN}[6/6] 클라이언트 개인키 생성 중...${NC}"
openssl genrsa -out client.key 4096

echo -e "${GREEN}[7/8] 클라이언트 CSR 생성 중...${NC}"
openssl req -new -key client.key -out client.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=Q-TLS Client/CN=QSIGN Client"

echo -e "${GREEN}[8/8] 클라이언트 인증서 서명 중 (CA로 서명)...${NC}"
# 클라이언트 인증 확장 속성
cat > client_ext.cnf << EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days $DAYS -in client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -extfile client_ext.cnf

rm client_ext.cnf

echo -e "${GREEN}[INFO] 클라이언트 인증서 생성 완료${NC}"
openssl x509 -in client.crt -noout -subject -issuer -dates

# ============================================================
# 정리 및 요약
# ============================================================
echo ""
echo -e "${GREEN}[SUCCESS] 모든 인증서 생성 완료!${NC}"
echo ""
echo "생성된 파일:"
echo "  CA 인증서:"
echo "    - ca.crt (CA 인증서)"
echo "    - ca.key (CA 개인키)"
echo ""
echo "  서버 인증서:"
echo "    - server.crt (서버 인증서)"
echo "    - server.key (서버 개인키)"
echo "    - server.csr (서버 CSR)"
echo ""
echo "  클라이언트 인증서:"
echo "    - client.crt (클라이언트 인증서)"
echo "    - client.key (클라이언트 개인키)"
echo "    - client.csr (클라이언트 CSR)"
echo ""

# 인증서 검증
echo "인증서 검증 중..."
echo ""

echo -e "${YELLOW}서버 인증서 검증:${NC}"
if openssl verify -CAfile ca.crt server.crt > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 서버 인증서 검증 성공${NC}"
else
    echo -e "${RED}✗ 서버 인증서 검증 실패${NC}"
fi

echo -e "${YELLOW}클라이언트 인증서 검증:${NC}"
if openssl verify -CAfile ca.crt client.crt > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 클라이언트 인증서 검증 성공${NC}"
else
    echo -e "${RED}✗ 클라이언트 인증서 검증 실패${NC}"
fi

echo ""
echo -e "${YELLOW}[주의사항]${NC}"
echo "1. 이 인증서들은 테스트 전용입니다."
echo "2. 프로덕션 환경에서는 신뢰할 수 있는 CA에서 발급받은 인증서를 사용하세요."
echo "3. 개인키 파일(*.key)은 안전하게 보관하세요."
echo "4. 상호 TLS 인증을 위해 서버는 ca.crt, server.crt, server.key가 필요합니다."
echo "5. 클라이언트는 ca.crt, client.crt, client.key가 필요합니다."
echo ""

# 권한 설정
chmod 600 *.key
chmod 644 *.crt

echo -e "${GREEN}[INFO] 파일 권한 설정 완료 (개인키: 600, 인증서: 644)${NC}"
echo ""
