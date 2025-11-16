#!/bin/bash
# Q-TLS 빌드 자동화 스크립트
# CMake를 사용한 전체 프로젝트 빌드

set -e  # 오류 발생 시 스크립트 중단

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 프로젝트 루트 디렉토리 확인
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
BUILD_TYPE="${1:-Release}"  # Debug 또는 Release (기본값: Release)

echo -e "${GREEN}=== Q-TLS 빌드 시작 ===${NC}"
echo "프로젝트 루트: $PROJECT_ROOT"
echo "빌드 타입: $BUILD_TYPE"

# 빌드 디렉토리 생성
if [ -d "$BUILD_DIR" ]; then
    echo -e "${YELLOW}기존 빌드 디렉토리 삭제 중...${NC}"
    rm -rf "$BUILD_DIR"
fi

echo "빌드 디렉토리 생성: $BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# CMake 구성
echo -e "${GREEN}CMake 구성 중...${NC}"
cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
      -DCMAKE_INSTALL_PREFIX="/usr/local" \
      "$PROJECT_ROOT"

# 병렬 빌드 (CPU 코어 수 자동 감지)
NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo -e "${GREEN}빌드 실행 중 (병렬도: $NPROC)...${NC}"
make -j"$NPROC"

# 빌드 결과 확인
if [ $? -eq 0 ]; then
    echo -e "${GREEN}=== 빌드 성공! ===${NC}"
    echo "빌드된 라이브러리: $BUILD_DIR/libqtls.so"
    echo "빌드된 테스트: $BUILD_DIR/tests/"
    echo "빌드된 예제: $BUILD_DIR/examples/"

    # 선택적: 테스트 실행
    if [ "$2" = "--with-tests" ]; then
        echo -e "${YELLOW}테스트 실행 중...${NC}"
        cd "$BUILD_DIR"
        ctest --output-on-failure
    fi
else
    echo -e "${RED}=== 빌드 실패 ===${NC}"
    exit 1
fi

echo -e "${GREEN}빌드 완료!${NC}"
echo "설치하려면: cd build && sudo make install"
