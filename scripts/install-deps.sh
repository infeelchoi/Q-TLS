#!/bin/bash
# Q-TLS 의존성 설치 스크립트
# liboqs, OpenSSL 및 기타 필수 라이브러리 설치

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Q-TLS 의존성 설치 시작 ===${NC}"

# OS 감지
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}지원되지 않는 운영체제입니다.${NC}"
    exit 1
fi

# 패키지 관리자별 설치
install_system_packages() {
    echo -e "${YELLOW}시스템 패키지 설치 중...${NC}"

    case $OS in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                git \
                libssl-dev \
                pkg-config \
                ninja-build \
                astyle \
                doxygen \
                graphviz
            ;;
        fedora|rhel|centos)
            sudo dnf install -y \
                gcc \
                gcc-c++ \
                cmake \
                git \
                openssl-devel \
                pkg-config \
                ninja-build \
                astyle \
                doxygen \
                graphviz
            ;;
        arch|manjaro)
            sudo pacman -Sy --noconfirm \
                base-devel \
                cmake \
                git \
                openssl \
                pkg-config \
                ninja \
                astyle \
                doxygen \
                graphviz
            ;;
        *)
            echo -e "${RED}지원되지 않는 배포판: $OS${NC}"
            exit 1
            ;;
    esac
}

# liboqs 설치
install_liboqs() {
    echo -e "${YELLOW}liboqs 설치 중...${NC}"

    LIBOQS_DIR="/tmp/liboqs"

    # 기존 디렉토리 삭제
    if [ -d "$LIBOQS_DIR" ]; then
        rm -rf "$LIBOQS_DIR"
    fi

    # liboqs 클론 및 빌드
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_DIR"
    cd "$LIBOQS_DIR"

    mkdir -p build
    cd build

    cmake -GNinja \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DBUILD_SHARED_LIBS=ON \
          -DOQS_USE_OPENSSL=ON \
          ..

    ninja
    sudo ninja install

    # 라이브러리 캐시 업데이트
    sudo ldconfig

    echo -e "${GREEN}liboqs 설치 완료!${NC}"
}

# OpenSSL 3.x 확인
check_openssl() {
    echo -e "${YELLOW}OpenSSL 버전 확인 중...${NC}"

    if command -v openssl &> /dev/null; then
        OPENSSL_VERSION=$(openssl version | awk '{print $2}')
        echo "설치된 OpenSSL 버전: $OPENSSL_VERSION"

        # 버전 3.x 이상 권장
        MAJOR_VERSION=$(echo "$OPENSSL_VERSION" | cut -d'.' -f1)
        if [ "$MAJOR_VERSION" -lt 3 ]; then
            echo -e "${YELLOW}경고: OpenSSL 3.x 이상을 권장합니다.${NC}"
        else
            echo -e "${GREEN}OpenSSL 버전 확인 완료!${NC}"
        fi
    else
        echo -e "${RED}OpenSSL이 설치되지 않았습니다.${NC}"
        exit 1
    fi
}

# Thales Luna HSM SDK 확인 (선택적)
check_luna_hsm() {
    echo -e "${YELLOW}Luna HSM SDK 확인 중...${NC}"

    if [ -d "/usr/safenet/lunaclient" ]; then
        echo -e "${GREEN}Luna HSM SDK 발견됨${NC}"
        export LUNA_HOME="/usr/safenet/lunaclient"
    else
        echo -e "${YELLOW}Luna HSM SDK를 찾을 수 없습니다 (선택적).${NC}"
        echo "HSM 기능을 사용하려면 Thales Luna HSM SDK를 설치하세요."
    fi
}

# 메인 설치 프로세스
main() {
    install_system_packages
    install_liboqs
    check_openssl
    check_luna_hsm

    echo ""
    echo -e "${GREEN}=== 의존성 설치 완료! ===${NC}"
    echo "다음 명령으로 Q-TLS를 빌드하세요:"
    echo "  ./scripts/build.sh"
}

main
