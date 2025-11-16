#!/bin/bash
# Q-TLS CLI 빠른 데모 스크립트

set -e

echo "╔════════════════════════════════════════════════════╗"
echo "║       Q-TLS CLI 빠른 데모                          ║"
echo "║  OpenSSL처럼 쉬운 양자 내성 암호화 도구            ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# 프로젝트 루트 찾기
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEMO_DIR="$PROJECT_ROOT/demo-output"

echo "프로젝트 루트: $PROJECT_ROOT"
echo "데모 출력 디렉토리: $DEMO_DIR"
echo ""

# qtls.sh 경로
QTLS="$PROJECT_ROOT/tools/qtls.sh"

if [ ! -f "$QTLS" ]; then
    echo "❌ qtls.sh를 찾을 수 없습니다: $QTLS"
    exit 1
fi

# 기존 데모 디렉토리 삭제
if [ -d "$DEMO_DIR" ]; then
    echo "⚠️  기존 데모 디렉토리 삭제 중..."
    rm -rf "$DEMO_DIR"
fi

mkdir -p "$DEMO_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 1단계: 전체 PKI 인프라 생성 (quickstart)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "명령어: qtls quickstart -d $DEMO_DIR/pki -cn demo.local"
echo ""

$QTLS quickstart -d "$DEMO_DIR/pki" -cn demo.local

echo ""
echo "✅ PKI 생성 완료!"
echo ""
ls -lh "$DEMO_DIR/pki/"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔑 2단계: Kyber768 키 쌍 생성"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# keygen이 설치되어 있는지 확인
if command -v keygen &> /dev/null || [ -x "$PROJECT_ROOT/tools/keygen/keygen" ]; then
    echo "명령어: qtls keygen kyber768 -o demo-kem -d $DEMO_DIR"
    echo ""

    $QTLS keygen kyber768 -o demo-kem -d "$DEMO_DIR"

    echo ""
    echo "✅ Kyber768 키 생성 완료!"
    echo ""
    ls -lh "$DEMO_DIR/demo-kem".*
    echo ""
else
    echo "⚠️  keygen이 빌드되지 않았습니다. 건너뜁니다."
    echo "   빌드 방법: cd tools/keygen && make"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔐 3단계: Dilithium3 서명 키 생성"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if command -v keygen &> /dev/null || [ -x "$PROJECT_ROOT/tools/keygen/keygen" ]; then
    echo "명령어: qtls keygen dilithium3 -o demo-sig -d $DEMO_DIR"
    echo ""

    $QTLS keygen dilithium3 -o demo-sig -d "$DEMO_DIR"

    echo ""
    echo "✅ Dilithium3 키 생성 완료!"
    echo ""
    ls -lh "$DEMO_DIR/demo-sig".*
    echo ""
else
    echo "⚠️  keygen이 빌드되지 않았습니다. 건너뜁니다."
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 4단계: 인증서 정보 확인"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if command -v openssl &> /dev/null; then
    echo "CA 인증서 Subject:"
    openssl x509 -in "$DEMO_DIR/pki/ca.crt" -noout -subject
    echo ""

    echo "CA 인증서 유효기간:"
    openssl x509 -in "$DEMO_DIR/pki/ca.crt" -noout -dates
    echo ""

    echo "서버 인증서 Subject:"
    openssl x509 -in "$DEMO_DIR/pki/server.crt" -noout -subject
    echo ""

    echo "서버 인증서 SAN:"
    openssl x509 -in "$DEMO_DIR/pki/server.crt" -noout -text | grep -A1 "Subject Alternative Name"
    echo ""

    echo "인증서 검증:"
    if openssl verify -CAfile "$DEMO_DIR/pki/ca.crt" "$DEMO_DIR/pki/server.crt" > /dev/null 2>&1; then
        echo "✅ 서버 인증서 검증 성공"
    else
        echo "❌ 서버 인증서 검증 실패"
    fi

    if openssl verify -CAfile "$DEMO_DIR/pki/ca.crt" "$DEMO_DIR/pki/client.crt" > /dev/null 2>&1; then
        echo "✅ 클라이언트 인증서 검증 성공"
    else
        echo "❌ 클라이언트 인증서 검증 실패"
    fi
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 5단계: 생성된 파일 요약"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "PKI 인증서 및 키:"
tree -L 2 "$DEMO_DIR" 2>/dev/null || find "$DEMO_DIR" -type f -ls

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 데모 완료!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "생성된 파일 위치: $DEMO_DIR"
echo ""
echo "다음 단계:"
echo "  1. 인증서 사용: Q-TLS 서버/클라이언트 예제 실행"
echo "     cd examples/simple-server"
echo "     ./simple_server --cert $DEMO_DIR/pki/server.crt --key $DEMO_DIR/pki/server.key"
echo ""
echo "  2. 추가 인증서 생성:"
echo "     $QTLS certgen server -cn newserver.com --ca-cert $DEMO_DIR/pki/ca.crt --ca-key $DEMO_DIR/pki/ca.key -o newserver"
echo ""
echo "  3. 전체 테스트 실행:"
echo "     ./scripts/run-all-tests.sh"
echo ""
echo "  4. 문서 읽기:"
echo "     cat QUICKSTART.md"
echo "     cat tools/README.md"
echo ""
