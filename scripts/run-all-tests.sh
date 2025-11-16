#!/bin/bash
# Q-TLS 전체 테스트 실행 스크립트
# 단위 테스트, 통합 테스트, 보안 테스트, 벤치마크 실행

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 프로젝트 루트 디렉토리
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
TEST_ENV="${PROJECT_ROOT}/test_env"

# 테스트 결과 저장
TEST_RESULTS=()
FAILED_TESTS=()

echo -e "${GREEN}=== Q-TLS 전체 테스트 시작 ===${NC}"

# 빌드 확인
check_build() {
    if [ ! -d "$BUILD_DIR" ]; then
        echo -e "${RED}빌드 디렉토리를 찾을 수 없습니다.${NC}"
        echo "먼저 빌드를 실행하세요: ./scripts/build.sh"
        exit 1
    fi
}

# 테스트 환경 확인
check_test_env() {
    if [ ! -d "$TEST_ENV" ]; then
        echo -e "${YELLOW}테스트 환경이 설정되지 않았습니다.${NC}"
        echo "테스트 환경 설정 중..."
        "$SCRIPT_DIR/setup-test-env.sh"
    fi

    # 환경 변수 로드
    if [ -f "$TEST_ENV/test.env" ]; then
        source "$TEST_ENV/test.env"
    fi
}

# 단위 테스트 실행
run_unit_tests() {
    echo -e "${BLUE}=== 단위 테스트 실행 ===${NC}"

    cd "$BUILD_DIR/tests/unit" 2>/dev/null || {
        echo -e "${YELLOW}단위 테스트가 빌드되지 않았습니다.${NC}"
        return
    }

    local unit_tests=(
        "test_kyber"
        "test_dilithium"
        "test_handshake"
        "test_session"
    )

    for test in "${unit_tests[@]}"; do
        if [ -x "./$test" ]; then
            echo -e "${YELLOW}실행 중: $test${NC}"
            if "./$test"; then
                TEST_RESULTS+=("✓ $test")
                echo -e "${GREEN}  성공${NC}"
            else
                FAILED_TESTS+=("$test")
                TEST_RESULTS+=("✗ $test")
                echo -e "${RED}  실패${NC}"
            fi
        fi
    done
}

# 통합 테스트 실행
run_integration_tests() {
    echo -e "${BLUE}=== 통합 테스트 실행 ===${NC}"

    cd "$BUILD_DIR/tests/integration" 2>/dev/null || {
        echo -e "${YELLOW}통합 테스트가 빌드되지 않았습니다.${NC}"
        return
    }

    local integration_tests=(
        "test_server_client"
        "test_mutual_tls"
        "test_qsign_integration"
    )

    for test in "${integration_tests[@]}"; do
        if [ -x "./$test" ]; then
            echo -e "${YELLOW}실행 중: $test${NC}"
            if "./$test"; then
                TEST_RESULTS+=("✓ $test")
                echo -e "${GREEN}  성공${NC}"
            else
                FAILED_TESTS+=("$test")
                TEST_RESULTS+=("✗ $test")
                echo -e "${RED}  실패${NC}"
            fi
        fi
    done

    # HSM 통합 테스트 (Luna HSM 있을 때만)
    if [ -d "/usr/safenet/lunaclient" ]; then
        echo -e "${YELLOW}실행 중: test_hsm_integration${NC}"
        if [ -x "./test_hsm_integration" ]; then
            if "./test_hsm_integration"; then
                TEST_RESULTS+=("✓ test_hsm_integration")
                echo -e "${GREEN}  성공${NC}"
            else
                FAILED_TESTS+=("test_hsm_integration")
                TEST_RESULTS+=("✗ test_hsm_integration")
                echo -e "${RED}  실패${NC}"
            fi
        fi
    fi
}

# 보안 테스트 실행
run_security_tests() {
    echo -e "${BLUE}=== 보안 테스트 실행 ===${NC}"

    cd "$BUILD_DIR/tests/security" 2>/dev/null || {
        echo -e "${YELLOW}보안 테스트가 빌드되지 않았습니다.${NC}"
        return
    }

    local security_tests=(
        "test_timing"
        "test_certificate_validation"
        "fuzz_handshake"
    )

    for test in "${security_tests[@]}"; do
        if [ -x "./$test" ]; then
            echo -e "${YELLOW}실행 중: $test${NC}"
            if "./$test"; then
                TEST_RESULTS+=("✓ $test")
                echo -e "${GREEN}  성공${NC}"
            else
                FAILED_TESTS+=("$test")
                TEST_RESULTS+=("✗ $test")
                echo -e "${RED}  실패${NC}"
            fi
        fi
    done
}

# 벤치마크 실행 (선택적)
run_benchmarks() {
    if [ "$1" != "--with-benchmark" ]; then
        return
    fi

    echo -e "${BLUE}=== 성능 벤치마크 실행 ===${NC}"

    cd "$BUILD_DIR/tools/benchmark" 2>/dev/null || {
        echo -e "${YELLOW}벤치마크가 빌드되지 않았습니다.${NC}"
        return
    }

    if [ -x "./benchmark" ]; then
        echo -e "${YELLOW}실행 중: benchmark${NC}"
        ./benchmark
        TEST_RESULTS+=("✓ benchmark")
    fi

    if [ -x "./benchmark_hsm" ] && [ -d "/usr/safenet/lunaclient" ]; then
        echo -e "${YELLOW}실행 중: benchmark_hsm${NC}"
        ./benchmark_hsm
        TEST_RESULTS+=("✓ benchmark_hsm")
    fi
}

# 테스트 결과 요약
print_summary() {
    echo ""
    echo -e "${GREEN}=== 테스트 결과 요약 ===${NC}"
    echo ""

    for result in "${TEST_RESULTS[@]}"; do
        echo "  $result"
    done

    echo ""
    local total=${#TEST_RESULTS[@]}
    local failed=${#FAILED_TESTS[@]}
    local passed=$((total - failed))

    echo "총 테스트: $total"
    echo -e "${GREEN}성공: $passed${NC}"

    if [ $failed -gt 0 ]; then
        echo -e "${RED}실패: $failed${NC}"
        echo ""
        echo "실패한 테스트:"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}✗ $test${NC}"
        done
        exit 1
    else
        echo -e "${GREEN}모든 테스트 성공!${NC}"
    fi
}

# 메인 실행
main() {
    check_build
    check_test_env

    run_unit_tests
    run_integration_tests
    run_security_tests
    run_benchmarks "$1"

    print_summary
}

# 사용법 출력
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "사용법: $0 [--with-benchmark]"
    echo ""
    echo "옵션:"
    echo "  --with-benchmark  성능 벤치마크 포함"
    echo "  --help, -h        도움말 표시"
    exit 0
fi

main "$@"
