#!/bin/bash
# 클라이언트 인증서 생성 스크립트 (Mutual TLS용)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-.}"
CLIENT_NAME="${2:-client}"

CA_CERT="$OUTPUT_DIR/ca-cert.pem"
CA_KEY="$OUTPUT_DIR/ca-key.pem"
CLIENT_CERT="$OUTPUT_DIR/client-cert.pem"
CLIENT_KEY="$OUTPUT_DIR/client-key.pem"

# CA 인증서 확인
if [ ! -f "$CA_CERT" ] || [ ! -f "$CA_KEY" ]; then
    echo "CA 인증서를 찾을 수 없습니다. 먼저 CA를 생성하세요:"
    echo "  ./generate-ca.sh $OUTPUT_DIR"
    exit 1
fi

echo "클라이언트 인증서 생성..."
echo "클라이언트 이름: $CLIENT_NAME"

# certgen 사용
if [ -x "$SCRIPT_DIR/certgen" ]; then
    "$SCRIPT_DIR/certgen" \
        -t client \
        -a dilithium3 \
        -s "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS/OU=Client/CN=$CLIENT_NAME" \
        -c "$CA_CERT" \
        -K "$CA_KEY" \
        -o "$CLIENT_CERT" \
        -k "$CLIENT_KEY"
else
    # OpenSSL fallback
    echo "certgen이 없습니다. OpenSSL 사용..."

    # 클라이언트 키 생성
    openssl genpkey -algorithm dilithium3 -out "$CLIENT_KEY" 2>/dev/null || {
        openssl genrsa -out "$CLIENT_KEY" 2048
    }

    # CSR 생성
    openssl req -new -key "$CLIENT_KEY" -out "$OUTPUT_DIR/client.csr" \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS/OU=Client/CN=$CLIENT_NAME"

    # 인증서 서명
    openssl x509 -req -in "$OUTPUT_DIR/client.csr" \
        -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$CLIENT_CERT" -days 365

    rm -f "$OUTPUT_DIR/client.csr"
fi

echo "클라이언트 인증서 생성 완료!"
echo "  인증서: $CLIENT_CERT"
echo "  키: $CLIENT_KEY"
