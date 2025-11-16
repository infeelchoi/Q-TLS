#!/bin/bash
# Q-TLS CLI 래퍼 스크립트
# C 프로그램이 없을 때도 동작하도록 Bash로 구현

set -e

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}" >&2; }
print_info() { echo -e "${CYAN}ℹ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }

# 메인 사용법
usage() {
    echo -e "${CYAN}Q-TLS CLI v${VERSION}${NC} - 양자 내성 암호화 통합 도구"
    echo ""
    echo "사용법: $0 <명령어> [옵션]"
    echo ""
    echo -e "${YELLOW}명령어:${NC}"
    echo "  keygen      키 쌍 생성 (Kyber, Dilithium)"
    echo "  certgen     인증서 생성 (CA, 서버, 클라이언트)"
    echo "  quickstart  빠른 시작 - CA + 서버 + 클라이언트 한번에 생성"
    echo "  verify      인증서/키 검증"
    echo "  info        인증서/키 정보 조회"
    echo "  version     버전 정보"
    echo "  help        도움말"
    echo ""
    echo -e "${YELLOW}빠른 예제:${NC}"
    echo "  $0 quickstart -d ./my-pki"
    echo "  $0 keygen kyber768 -o mykey"
    echo "  $0 certgen server -cn myserver.com -o server"
}

# quickstart 명령
cmd_quickstart() {
    local dir="./qtls-pki"
    local server_cn="localhost"
    local algorithm="dilithium3"
    local verbose=0

    # 옵션 파싱
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dir)
                dir="$2"
                shift 2
                ;;
            -cn|--server-cn)
                server_cn="$2"
                shift 2
                ;;
            -a|--algorithm)
                algorithm="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=1
                shift
                ;;
            -h|--help)
                echo "Q-TLS 빠른 시작"
                echo ""
                echo "사용법: $0 quickstart [옵션]"
                echo ""
                echo "옵션:"
                echo "  -d, --dir PATH        출력 디렉토리 (기본: ./qtls-pki)"
                echo "  -cn, --server-cn NAME 서버 CN (기본: localhost)"
                echo "  -a, --algorithm ALG   알고리즘 (기본: dilithium3)"
                echo "  -v, --verbose         상세 출력"
                return 0
                ;;
            *)
                print_error "알 수 없는 옵션: $1"
                return 1
                ;;
        esac
    done

    echo -e "${CYAN}=== Q-TLS 빠른 시작 ===${NC}"
    echo ""
    echo "디렉토리: $dir"
    echo "서버 CN: $server_cn"
    echo "알고리즘: $algorithm"
    echo ""

    # 디렉토리 생성
    mkdir -p "$dir"

    # certgen 경로 찾기
    local certgen=""
    if command -v certgen &> /dev/null; then
        certgen="certgen"
    elif [ -x "$SCRIPT_DIR/certgen/certgen" ]; then
        certgen="$SCRIPT_DIR/certgen/certgen"
    else
        print_error "certgen을 찾을 수 없습니다. 먼저 빌드하세요: cd tools/certgen && make"
        return 1
    fi

    local verbose_flag=""
    [ $verbose -eq 1 ] && verbose_flag="" || verbose_flag="2>/dev/null"

    # 1. CA 생성
    echo -e "${YELLOW}[1/3] CA 인증서 생성${NC}"
    if eval "$certgen -t ca -a $algorithm -s '/C=KR/O=Q-TLS/CN=Q-TLS Root CA' -d 3650 -o $dir/ca.crt -k $dir/ca.key $verbose_flag"; then
        print_success "CA 생성 완료"
    else
        print_error "CA 생성 실패"
        return 1
    fi

    # 2. 서버 인증서
    echo ""
    echo -e "${YELLOW}[2/3] 서버 인증서 생성${NC}"
    if eval "$certgen -t server -a $algorithm -s '/C=KR/O=Q-TLS/CN=$server_cn' -c $dir/ca.crt -K $dir/ca.key -o $dir/server.crt -k $dir/server.key -n $server_cn -n www.$server_cn $verbose_flag"; then
        print_success "서버 인증서 생성 완료"
    else
        print_error "서버 인증서 생성 실패"
        return 1
    fi

    # 3. 클라이언트 인증서
    echo ""
    echo -e "${YELLOW}[3/3] 클라이언트 인증서 생성${NC}"
    if eval "$certgen -t client -a $algorithm -s '/C=KR/O=Q-TLS/CN=Q-TLS Client' -c $dir/ca.crt -K $dir/ca.key -o $dir/client.crt -k $dir/client.key $verbose_flag"; then
        print_success "클라이언트 인증서 생성 완료"
    else
        print_error "클라이언트 인증서 생성 실패"
        return 1
    fi

    # README 생성
    cat > "$dir/README.txt" <<EOF
Q-TLS PKI 인프라
================

생성일: $(date)
알고리즘: $algorithm
서버 CN: $server_cn

파일 목록:
  ca.crt, ca.key         - CA 인증서 및 키
  server.crt, server.key - 서버 인증서 및 키
  client.crt, client.key - 클라이언트 인증서 및 키

사용 예제:
  서버 실행:
    qtls-server --cert server.crt --key server.key --ca ca.crt

  클라이언트 연결:
    qtls-client --cert client.crt --key client.key --ca ca.crt

보안 권장사항:
  chmod 600 *.key  # 키 파일 권한 설정

인증서 정보 확인:
  openssl x509 -in server.crt -text -noout
EOF

    echo ""
    echo -e "${GREEN}=== 완료! ===${NC}"
    echo ""
    echo "생성된 파일:"
    echo "  $dir/ca.crt, ca.key"
    echo "  $dir/server.crt, server.key"
    echo "  $dir/client.crt, client.key"
    echo "  $dir/README.txt"
    echo ""
    echo -e "${YELLOW}권장:${NC} 비밀키 권한 설정"
    echo "  chmod 600 $dir/*.key"
}

# keygen 명령
cmd_keygen() {
    if [ $# -lt 1 ]; then
        print_error "알고리즘을 지정하세요"
        echo "사용법: $0 keygen <알고리즘> -o <출력파일>"
        echo "알고리즘: kyber512, kyber768, kyber1024, dilithium2, dilithium3, dilithium5"
        return 1
    fi

    local algorithm="$1"
    shift

    local output="qtls_key"
    local dir="."
    local verbose=0

    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                output="$2"
                shift 2
                ;;
            -d|--dir)
                dir="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=1
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    # keygen 찾기
    local keygen=""
    if command -v keygen &> /dev/null; then
        keygen="keygen"
    elif [ -x "$SCRIPT_DIR/keygen/keygen" ]; then
        keygen="$SCRIPT_DIR/keygen/keygen"
    else
        print_error "keygen을 찾을 수 없습니다. 먼저 빌드하세요: cd tools/keygen && make"
        return 1
    fi

    mkdir -p "$dir"

    # 키 타입 결정
    local key_type=""
    local alg_name=""

    case $algorithm in
        kyber512)
            key_type="kem"
            alg_name="Kyber512"
            ;;
        kyber768)
            key_type="kem"
            alg_name="Kyber768"
            ;;
        kyber1024)
            key_type="kem"
            alg_name="Kyber1024"
            ;;
        dilithium2)
            key_type="sig"
            alg_name="Dilithium2"
            ;;
        dilithium3)
            key_type="sig"
            alg_name="Dilithium3"
            ;;
        dilithium5)
            key_type="sig"
            alg_name="Dilithium5"
            ;;
        *)
            print_error "지원하지 않는 알고리즘: $algorithm"
            return 1
            ;;
    esac

    echo -e "${YELLOW}$alg_name 키 쌍 생성 중...${NC}"

    local verbose_flag=""
    [ $verbose -eq 1 ] && verbose_flag="-v"

    if $keygen -t $key_type -a $alg_name -p "$dir/$output.pub" -s "$dir/$output.key" $verbose_flag; then
        print_success "키 생성 완료!"
        echo "  공개키: $dir/$output.pub"
        echo "  비밀키: $dir/$output.key"
    else
        print_error "키 생성 실패"
        return 1
    fi
}

# certgen 명령 (간단한 래퍼)
cmd_certgen() {
    local certgen=""
    if command -v certgen &> /dev/null; then
        certgen="certgen"
    elif [ -x "$SCRIPT_DIR/certgen/certgen" ]; then
        certgen="$SCRIPT_DIR/certgen/certgen"
    else
        print_error "certgen을 찾을 수 없습니다"
        return 1
    fi

    echo "certgen 명령어를 직접 사용하는 것을 권장합니다."
    echo "또는 'qtls quickstart'로 전체 PKI를 생성하세요."
}

# info 명령
cmd_info() {
    if [ $# -lt 1 ]; then
        print_error "파일을 지정하세요"
        return 1
    fi

    local file="$1"

    if [ ! -f "$file" ]; then
        print_error "파일을 찾을 수 없습니다: $file"
        return 1
    fi

    # 파일 타입 감지
    if openssl x509 -in "$file" -noout 2>/dev/null; then
        echo -e "${CYAN}=== 인증서 정보 ===${NC}"
        openssl x509 -in "$file" -text -noout
    elif openssl pkey -in "$file" -noout 2>/dev/null; then
        echo -e "${CYAN}=== 키 정보 ===${NC}"
        openssl pkey -in "$file" -text -noout
    else
        print_error "인식할 수 없는 파일 형식"
        return 1
    fi
}

# 메인
main() {
    if [ $# -lt 1 ]; then
        usage
        exit 1
    fi

    local command="$1"
    shift

    case "$command" in
        keygen)
            cmd_keygen "$@"
            ;;
        certgen)
            cmd_certgen "$@"
            ;;
        quickstart)
            cmd_quickstart "$@"
            ;;
        info)
            cmd_info "$@"
            ;;
        version|-v|--version)
            echo "Q-TLS CLI v$VERSION"
            ;;
        help|-h|--help)
            usage
            ;;
        *)
            print_error "알 수 없는 명령어: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
