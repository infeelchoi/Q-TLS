# Q-TLS Mutual TLS Example Makefile
# 상호 TLS 인증 예제 빌드 파일

# 컴파일러 설정
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lqtls -loqs -lssl -lcrypto -lpthread -lm

# 경로 설정
QTLS_INCLUDE = ../../include
QTLS_LIB = ../../build

# 타겟
SERVER_TARGET = mtls_server
CLIENT_TARGET = mtls_client

SERVER_SRC = mtls_server.c
CLIENT_SRC = mtls_client.c

SERVER_OBJ = $(SERVER_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)

# 기본 타겟
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# 서버 빌드
$(SERVER_TARGET): $(SERVER_OBJ)
	@echo "링킹: $(SERVER_TARGET)"
	$(CC) -o $@ $^ -L$(QTLS_LIB) $(LDFLAGS)
	@echo "빌드 완료: $(SERVER_TARGET)"

# 클라이언트 빌드
$(CLIENT_TARGET): $(CLIENT_OBJ)
	@echo "링킹: $(CLIENT_TARGET)"
	$(CC) -o $@ $^ -L$(QTLS_LIB) $(LDFLAGS)
	@echo "빌드 완료: $(CLIENT_TARGET)"

# 오브젝트 파일 생성
%.o: %.c
	@echo "컴파일: $<"
	$(CC) $(CFLAGS) -I$(QTLS_INCLUDE) -c $< -o $@

# 인증서 생성
certs:
	@echo "CA 및 인증서 생성 중..."
	@bash generate_certs.sh

# 서버 실행
run-server: $(SERVER_TARGET) check-certs
	@echo "서버 시작 중..."
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH ./$(SERVER_TARGET)

# 클라이언트 실행
run-client: $(CLIENT_TARGET) check-certs
	@echo "클라이언트 시작 중..."
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH ./$(CLIENT_TARGET)

# 인증서 확인
check-certs:
	@if [ ! -d certs ]; then \
		echo "인증서 디렉토리가 없습니다. 'make certs'를 실행하세요."; \
		exit 1; \
	fi
	@if [ ! -f certs/ca.crt ] || [ ! -f certs/server.crt ] || [ ! -f certs/client.crt ]; then \
		echo "인증서가 없습니다. 'make certs'를 실행하세요."; \
		exit 1; \
	fi

# 전체 테스트 (서버와 클라이언트를 별도 터미널에서 실행해야 함)
test: all check-certs
	@echo "============================================="
	@echo " 상호 TLS 테스트 준비 완료"
	@echo "============================================="
	@echo ""
	@echo "다음 명령어를 별도 터미널에서 실행하세요:"
	@echo ""
	@echo "터미널 1 (서버):"
	@echo "  make run-server"
	@echo ""
	@echo "터미널 2 (클라이언트):"
	@echo "  make run-client"
	@echo ""

# 인증서 정보 확인
verify-certs: check-certs
	@echo "========== CA 인증서 정보 =========="
	@openssl x509 -in certs/ca.crt -noout -text -subject -issuer -dates
	@echo ""
	@echo "========== 서버 인증서 정보 =========="
	@openssl x509 -in certs/server.crt -noout -text -subject -issuer -dates
	@echo ""
	@echo "========== 클라이언트 인증서 정보 =========="
	@openssl x509 -in certs/client.crt -noout -text -subject -issuer -dates

# 정리
clean:
	@echo "빌드 파일 삭제 중..."
	rm -f $(SERVER_OBJ) $(CLIENT_OBJ) $(SERVER_TARGET) $(CLIENT_TARGET)

# 전체 정리 (인증서 포함)
distclean: clean
	@echo "인증서 및 설정 파일 삭제 중..."
	rm -rf certs/

# 도움말
help:
	@echo "Q-TLS Mutual TLS Example Makefile"
	@echo ""
	@echo "사용 가능한 타겟:"
	@echo "  make              - 서버와 클라이언트 빌드"
	@echo "  make certs        - CA 및 인증서 생성"
	@echo "  make run-server   - 서버 실행"
	@echo "  make run-client   - 클라이언트 실행"
	@echo "  make test         - 테스트 안내 표시"
	@echo "  make verify-certs - 인증서 정보 확인"
	@echo "  make clean        - 빌드 파일 삭제"
	@echo "  make distclean    - 빌드 파일 및 인증서 삭제"
	@echo "  make help         - 이 도움말 표시"

.PHONY: all certs run-server run-client check-certs test verify-certs clean distclean help
