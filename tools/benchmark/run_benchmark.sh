#!/bin/bash
#
# Q-TLS 자동 벤치마크 스크립트
# 다양한 설정으로 성능 측정 및 결과 저장
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUTPUT_DIR="benchmark_results"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="$OUTPUT_DIR/benchmark_$TIMESTAMP.txt"

echo "Q-TLS 자동 벤치마크 시작"
echo "결과 파일: $RESULT_FILE"
echo ""

# 시스템 정보 수집
{
    echo "=========================================="
    echo "시스템 정보"
    echo "=========================================="
    echo "날짜: $(date)"
    echo "호스트: $(hostname)"
    echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
    echo "메모리: $(free -h | grep Mem | awk '{print $2}')"
    echo "OS: $(uname -a)"
    echo ""
} | tee "$RESULT_FILE"

# 벤치마크 빌드
echo "벤치마크 빌드 중..."
make clean > /dev/null
make all

# 벤치마크 실행
echo "벤치마크 실행 중..."
echo ""

LD_LIBRARY_PATH=../../build ./benchmark | tee -a "$RESULT_FILE"

echo ""
echo "=========================================="
echo "벤치마크 완료!"
echo "결과 저장: $RESULT_FILE"
echo "=========================================="
