#!/bin/bash
# Q-TLS 테스트 환경 설정 스크립트
# 테스트 인증서, 키 생성 및 테스트 디렉토리 구성

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 프로젝트 루트 디렉토리
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR="${PROJECT_ROOT}/test_env"

echo -e "${GREEN}=== Q-TLS 테스트 환경 설정 ===${NC}"

# 테스트 디렉토리 생성
echo "테스트 디렉토리 생성: $TEST_DIR"
mkdir -p "$TEST_DIR"/{certs,keys,logs}

# CA 인증서 생성
generate_ca_cert() {
    echo -e "${YELLOW}CA 인증서 생성 중...${NC}"

    cd "$TEST_DIR/certs"

    # CA 개인키 생성 (Dilithium3)
    openssl genpkey -algorithm dilithium3 -out ca-key.pem 2>/dev/null || {
        echo -e "${YELLOW}Dilithium3 실패, RSA 사용${NC}"
        openssl genrsa -out ca-key.pem 4096
    }

    # CA 인증서 생성
    openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS Test/OU=Test CA/CN=Q-TLS Test CA"

    echo -e "${GREEN}CA 인증서 생성 완료${NC}"
}

# 서버 인증서 생성
generate_server_cert() {
    echo -e "${YELLOW}서버 인증서 생성 중...${NC}"

    cd "$TEST_DIR/certs"

    # 서버 개인키 생성
    openssl genpkey -algorithm dilithium3 -out server-key.pem 2>/dev/null || {
        openssl genrsa -out server-key.pem 2048
    }

    # CSR 생성
    openssl req -new -key server-key.pem -out server.csr \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS Test/OU=Test Server/CN=localhost"

    # 서버 인증서 서명
    openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
        -CAcreateserial -out server-cert.pem -days 365

    rm -f server.csr

    echo -e "${GREEN}서버 인증서 생성 완료${NC}"
}

# 클라이언트 인증서 생성 (mTLS용)
generate_client_cert() {
    echo -e "${YELLOW}클라이언트 인증서 생성 중...${NC}"

    cd "$TEST_DIR/certs"

    # 클라이언트 개인키 생성
    openssl genpkey -algorithm dilithium3 -out client-key.pem 2>/dev/null || {
        openssl genrsa -out client-key.pem 2048
    }

    # CSR 생성
    openssl req -new -key client-key.pem -out client.csr \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Q-TLS Test/OU=Test Client/CN=test-client"

    # 클라이언트 인증서 서명
    openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
        -CAcreateserial -out client-cert.pem -days 365

    rm -f client.csr

    echo -e "${GREEN}클라이언트 인증서 생성 완료${NC}"
}

# 테스트 키 생성 (Kyber, Dilithium)
generate_test_keys() {
    echo -e "${YELLOW}양자 내성 키 생성 중...${NC}"

    cd "$TEST_DIR/keys"

    # Kyber-768 키 쌍 생성 (KEM)
    if command -v oqs-gen &> /dev/null; then
        oqs-gen kyber768 kyber768_private.key kyber768_public.key
        echo "Kyber-768 키 생성 완료"
    else
        echo -e "${YELLOW}oqs-gen을 찾을 수 없습니다. 건너뜁니다.${NC}"
    fi

    # Dilithium3 키 쌍 생성 (서명)
    openssl genpkey -algorithm dilithium3 -out dilithium3_private.pem 2>/dev/null || {
        echo -e "${YELLOW}Dilithium3 키 생성 건너뜀${NC}"
    }

    echo -e "${GREEN}테스트 키 생성 완료${NC}"
}

# 환경 변수 설정 파일 생성
create_env_file() {
    echo -e "${YELLOW}환경 변수 파일 생성 중...${NC}"

    cat > "$TEST_DIR/test.env" <<EOF
# Q-TLS 테스트 환경 변수
export QTLS_TEST_DIR="$TEST_DIR"
export QTLS_CA_CERT="$TEST_DIR/certs/ca-cert.pem"
export QTLS_CA_KEY="$TEST_DIR/certs/ca-key.pem"
export QTLS_SERVER_CERT="$TEST_DIR/certs/server-cert.pem"
export QTLS_SERVER_KEY="$TEST_DIR/certs/server-key.pem"
export QTLS_CLIENT_CERT="$TEST_DIR/certs/client-cert.pem"
export QTLS_CLIENT_KEY="$TEST_DIR/certs/client-key.pem"
export QTLS_LOG_DIR="$TEST_DIR/logs"

# Luna HSM (선택적)
export LUNA_HOME="/usr/safenet/lunaclient"
export CKR_LIBRARY_PATH="\$LUNA_HOME/libs/64"

# 테스트 서버 설정
export QTLS_TEST_SERVER_PORT=8443
export QTLS_TEST_SERVER_HOST=localhost

echo "Q-TLS 테스트 환경 로드됨"
EOF

    echo -e "${GREEN}환경 변수 파일 생성: $TEST_DIR/test.env${NC}"
}

# 메인 실행
main() {
    generate_ca_cert
    generate_server_cert
    generate_client_cert
    generate_test_keys
    create_env_file

    echo ""
    echo -e "${GREEN}=== 테스트 환경 설정 완료! ===${NC}"
    echo "생성된 파일:"
    echo "  - CA 인증서: $TEST_DIR/certs/ca-cert.pem"
    echo "  - 서버 인증서: $TEST_DIR/certs/server-cert.pem"
    echo "  - 클라이언트 인증서: $TEST_DIR/certs/client-cert.pem"
    echo "  - 환경 변수: $TEST_DIR/test.env"
    echo ""
    echo "테스트 환경 로드:"
    echo "  source $TEST_DIR/test.env"
}

main
