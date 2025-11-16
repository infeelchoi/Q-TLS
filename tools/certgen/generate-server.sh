#!/bin/bash
# 서버 인증서 생성 스크립트

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-.}"
SERVER_NAME="${2:-localhost}"

CA_CERT="$OUTPUT_DIR/ca-cert.pem"
CA_KEY="$OUTPUT_DIR/ca-key.pem"
SERVER_CERT="$OUTPUT_DIR/server-cert.pem"
SERVER_KEY="$OUTPUT_DIR/server-key.pem"

# CA 인증서 확인
if [ ! -f "$CA_CERT" ] || [ ! -f "$CA_KEY" ]; then
    echo "CA 인증서를 찾을 수 없습니다. 먼저 CA를 생성하세요:"
    echo "  ./generate-ca.sh $OUTPUT_DIR"
    exit 1
fi

echo "서버 인증서 생성..."
echo "서버 이름: $SERVER_NAME"

# certgen 사용
if [ -x "$SCRIPT_DIR/certgen" ]; then
    "$SCRIPT_DIR/certgen" \
        -t server \
        -a dilithium3 \
        -s "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS/OU=Server/CN=$SERVER_NAME" \
        -c "$CA_CERT" \
        -K "$CA_KEY" \
        -o "$SERVER_CERT" \
        -k "$SERVER_KEY" \
        -n "$SERVER_NAME" \
        -n "www.$SERVER_NAME"
else
    # OpenSSL fallback
    echo "certgen이 없습니다. OpenSSL 사용..."

    # 서버 키 생성
    openssl genpkey -algorithm dilithium3 -out "$SERVER_KEY" 2>/dev/null || {
        openssl genrsa -out "$SERVER_KEY" 2048
    }

    # CSR 생성
    openssl req -new -key "$SERVER_KEY" -out "$OUTPUT_DIR/server.csr" \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS/OU=Server/CN=$SERVER_NAME"

    # SAN 설정 파일 생성
    cat > "$OUTPUT_DIR/server-san.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_NAME
DNS.2 = www.$SERVER_NAME
EOF

    # 인증서 서명
    openssl x509 -req -in "$OUTPUT_DIR/server.csr" \
        -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$SERVER_CERT" -days 365 \
        -extfile "$OUTPUT_DIR/server-san.cnf" -extensions v3_req

    rm -f "$OUTPUT_DIR/server.csr" "$OUTPUT_DIR/server-san.cnf"
fi

echo "서버 인증서 생성 완료!"
echo "  인증서: $SERVER_CERT"
echo "  키: $SERVER_KEY"
