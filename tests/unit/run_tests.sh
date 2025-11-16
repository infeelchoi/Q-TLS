#!/bin/bash
#
# Q-TLS 단위 테스트 실행 스크립트
# 모든 단위 테스트를 순차적으로 실행하고 결과를 보고
#
# 사용법: ./run_tests.sh [옵션]
#   --verbose : 상세 출력
#   --stop-on-fail : 첫 실패 시 중단
#   --valgrind : 메모리 누수 검사
#

set -e

# 색상 정의
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# 옵션 파싱
VERBOSE=0
STOP_ON_FAIL=0
USE_VALGRIND=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose)
            VERBOSE=1
            shift
            ;;
        --stop-on-fail)
            STOP_ON_FAIL=1
            shift
            ;;
        --valgrind)
            USE_VALGRIND=1
            shift
            ;;
        *)
            echo "알 수 없는 옵션: $1"
            echo "사용법: $0 [--verbose] [--stop-on-fail] [--valgrind]"
            exit 1
            ;;
    esac
done

# 작업 디렉토리 확인
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "=========================================="
echo "  Q-TLS 단위 테스트 실행"
echo "=========================================="
echo ""

# Q-TLS 라이브러리 빌드 확인
if [ ! -f "../../build/libqtls.so" ]; then
    echo -e "${YELLOW}경고: Q-TLS 라이브러리가 빌드되지 않았습니다.${NC}"
    echo "먼저 Q-TLS를 빌드하세요:"
    echo "  cd ../../build && cmake .. && make"
    exit 1
fi

# 테스트 빌드
echo -e "${YELLOW}테스트 빌드 중...${NC}"
make clean > /dev/null 2>&1 || true
if ! make all; then
    echo -e "${RED}테스트 빌드 실패!${NC}"
    exit 1
fi
echo -e "${GREEN}테스트 빌드 완료${NC}"
echo ""

# 테스트 목록
TESTS=(
    "test_kyber:KYBER1024 암호화"
    "test_dilithium:DILITHIUM3 서명"
    "test_handshake:핸드셰이크 프로토콜"
    "test_session:세션 관리"
)

# 테스트 결과 추적
TOTAL_TESTS=${#TESTS[@]}
PASSED_TESTS=0
FAILED_TESTS=0
FAILED_TEST_NAMES=()

# LD_LIBRARY_PATH 설정
export LD_LIBRARY_PATH="../../build:$LD_LIBRARY_PATH"

# Valgrind 옵션
VALGRIND_CMD=""
if [ $USE_VALGRIND -eq 1 ]; then
    if ! command -v valgrind &> /dev/null; then
        echo -e "${YELLOW}경고: valgrind가 설치되지 않았습니다.${NC}"
        USE_VALGRIND=0
    else
        VALGRIND_CMD="valgrind --leak-check=full --error-exitcode=1 --quiet"
        echo -e "${YELLOW}메모리 누수 검사 활성화 (Valgrind)${NC}"
        echo ""
    fi
fi

# 각 테스트 실행
for test_entry in "${TESTS[@]}"; do
    IFS=':' read -r test_name test_desc <<< "$test_entry"

    echo -e "${YELLOW}[실행]${NC} $test_desc ($test_name)"

    if [ $VERBOSE -eq 1 ]; then
        # 상세 모드: 모든 출력 표시
        if $VALGRIND_CMD ./$test_name; then
            echo -e "${GREEN}[통과]${NC} $test_desc"
            ((PASSED_TESTS++))
        else
            echo -e "${RED}[실패]${NC} $test_desc"
            ((FAILED_TESTS++))
            FAILED_TEST_NAMES+=("$test_desc")
            if [ $STOP_ON_FAIL -eq 1 ]; then
                echo ""
                echo -e "${RED}첫 실패에서 중단됨${NC}"
                exit 1
            fi
        fi
    else
        # 조용한 모드: 결과만 표시
        if $VALGRIND_CMD ./$test_name > /tmp/${test_name}.log 2>&1; then
            echo -e "${GREEN}[통과]${NC} $test_desc"
            ((PASSED_TESTS++))
        else
            echo -e "${RED}[실패]${NC} $test_desc"
            echo "  로그: /tmp/${test_name}.log"
            ((FAILED_TESTS++))
            FAILED_TEST_NAMES+=("$test_desc")
            if [ $STOP_ON_FAIL -eq 1 ]; then
                echo ""
                echo -e "${RED}첫 실패에서 중단됨${NC}"
                cat /tmp/${test_name}.log
                exit 1
            fi
        fi
    fi
    echo ""
done

# 최종 결과 출력
echo "=========================================="
echo "  테스트 결과 요약"
echo "=========================================="
echo "총 테스트: $TOTAL_TESTS"
echo -e "통과: ${GREEN}$PASSED_TESTS${NC}"
echo -e "실패: ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}실패한 테스트:${NC}"
    for failed_test in "${FAILED_TEST_NAMES[@]}"; do
        echo "  - $failed_test"
    done
    echo ""
    echo "=========================================="
    exit 1
else
    echo -e "${GREEN}모든 단위 테스트 통과!${NC}"
    echo "=========================================="
    exit 0
fi
