#!/bin/bash
#
# Q-TLS 서버 인증서 생성 스크립트
#
# 이 스크립트는 테스트용 자체 서명 인증서를 생성합니다.
# 프로덕션 환경에서는 신뢰할 수 있는 CA에서 발급한 인증서를 사용하세요.
#

set -e

echo "=========================================="
echo " Q-TLS 서버 인증서 생성"
echo "=========================================="
echo ""

# 설정 변수
CERT_FILE="server.crt"
KEY_FILE="server.key"
CSR_FILE="server.csr"
DAYS=365
COUNTRY="KR"
STATE="Seoul"
LOCALITY="Seoul"
ORGANIZATION="QSIGN Project"
ORG_UNIT="Q-TLS Development"
COMMON_NAME="localhost"

echo "[INFO] 서버 개인키 생성 중..."
openssl genrsa -out $KEY_FILE 4096

echo "[INFO] 인증서 서명 요청(CSR) 생성 중..."
openssl req -new -key $KEY_FILE -out $CSR_FILE \
    -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORG_UNIT/CN=$COMMON_NAME"

echo "[INFO] 자체 서명 인증서 생성 중..."
openssl x509 -req -days $DAYS -in $CSR_FILE -signkey $KEY_FILE -out $CERT_FILE \
    -extfile <(printf "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1")

echo ""
echo "[SUCCESS] 인증서 생성 완료!"
echo ""
echo "생성된 파일:"
echo "  - 서버 인증서: $CERT_FILE"
echo "  - 서버 개인키: $KEY_FILE"
echo "  - CSR 파일: $CSR_FILE"
echo ""

echo "인증서 정보:"
openssl x509 -in $CERT_FILE -noout -subject -dates

echo ""
echo "[주의] 이 인증서는 테스트 전용입니다."
echo "       프로덕션 환경에서는 신뢰할 수 있는 CA에서 발급한 인증서를 사용하세요."
echo ""
