#!/bin/bash
# CA 인증서 생성 스크립트

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-.}"

CA_CERT="$OUTPUT_DIR/ca-cert.pem"
CA_KEY="$OUTPUT_DIR/ca-key.pem"

echo "CA 인증서 생성..."
echo "출력 디렉토리: $OUTPUT_DIR"

# certgen 사용 (빌드되어 있으면)
if [ -x "$SCRIPT_DIR/certgen" ]; then
    "$SCRIPT_DIR/certgen" \
        -t ca \
        -a dilithium3 \
        -s "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS/OU=Certificate Authority/CN=Q-TLS Root CA" \
        -d 3650 \
        -o "$CA_CERT" \
        -k "$CA_KEY"
else
    # OpenSSL fallback
    echo "certgen이 없습니다. OpenSSL 사용..."

    # Dilithium3 시도
    openssl genpkey -algorithm dilithium3 -out "$CA_KEY" 2>/dev/null || {
        echo "Dilithium3 지원 안 됨, RSA 사용"
        openssl genrsa -out "$CA_KEY" 4096
    }

    # CA 인증서 생성
    openssl req -new -x509 -days 3650 -key "$CA_KEY" -out "$CA_CERT" \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS/OU=Certificate Authority/CN=Q-TLS Root CA"
fi

echo "CA 인증서 생성 완료!"
echo "  인증서: $CA_CERT"
echo "  키: $CA_KEY"
