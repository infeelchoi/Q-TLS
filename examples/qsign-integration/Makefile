# Q-TLS QSIGN Integration Example Makefile
# QSIGN PKI 및 HSM 통합 예제 빌드 파일

# 컴파일러 설정
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -DPRODUCTION_MODE
CFLAGS_TEST = -Wall -Wextra -O2 -std=c11  # 테스트 모드 (검증 완화)

# 라이브러리
QTLS_LIBS = -lqtls -loqs -lssl -lcrypto -lpthread -lm
VAULT_LIBS = -lcurl -ljansson

# 경로
QTLS_INCLUDE = ../../include
QTLS_LIB = ../../build

# 타겟
SERVER_TARGET = qsign_server
CLIENT_TARGET = qsign_client
VAULT_TARGET = vault_integration

SERVER_SRC = qsign_server.c
CLIENT_SRC = qsign_client.c
VAULT_SRC = vault_integration.c

SERVER_OBJ = $(SERVER_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)
VAULT_OBJ = $(VAULT_SRC:.c=.o)

# 기본 타겟
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# 전체 (Vault 포함)
all-with-vault: all $(VAULT_TARGET)

# 서버 빌드
$(SERVER_TARGET): $(SERVER_OBJ)
	@echo "링킹: $(SERVER_TARGET)"
	$(CC) -o $@ $^ -L$(QTLS_LIB) $(QTLS_LIBS)
	@echo "빌드 완료: $(SERVER_TARGET)"

# 클라이언트 빌드
$(CLIENT_TARGET): $(CLIENT_OBJ)
	@echo "링킹: $(CLIENT_TARGET)"
	$(CC) -o $@ $^ -L$(QTLS_LIB) $(QTLS_LIBS)
	@echo "빌드 완료: $(CLIENT_TARGET)"

# Vault 통합 빌드
$(VAULT_TARGET): $(VAULT_OBJ)
	@echo "링킹: $(VAULT_TARGET)"
	$(CC) -o $@ $^ -L$(QTLS_LIB) $(QTLS_LIBS) $(VAULT_LIBS)
	@echo "빌드 완료: $(VAULT_TARGET)"

# 오브젝트 파일 생성
%.o: %.c
	@echo "컴파일: $<"
	$(CC) $(CFLAGS) -I$(QTLS_INCLUDE) -c $< -o $@

# 테스트 모드 빌드 (검증 완화)
test-mode:
	@echo "테스트 모드로 빌드 중..."
	$(CC) $(CFLAGS_TEST) -I$(QTLS_INCLUDE) -c $(SERVER_SRC) -o $(SERVER_OBJ)
	$(CC) -o $(SERVER_TARGET) $(SERVER_OBJ) -L$(QTLS_LIB) $(QTLS_LIBS)
	$(CC) $(CFLAGS_TEST) -I$(QTLS_INCLUDE) -c $(CLIENT_SRC) -o $(CLIENT_OBJ)
	$(CC) -o $(CLIENT_TARGET) $(CLIENT_OBJ) -L$(QTLS_LIB) $(QTLS_LIBS)
	@echo "테스트 모드 빌드 완료"

# 인증서 디렉토리 생성
setup-certs:
	@echo "인증서 디렉토리 구조 생성 중..."
	@mkdir -p certs
	@mkdir -p /tmp/qsign-test/ca
	@mkdir -p /tmp/qsign-test/certs
	@mkdir -p /tmp/qsign-test/crl
	@echo "디렉토리 생성 완료"

# 테스트 인증서 생성 (실제 QSIGN PKI 없이 테스트용)
test-certs: setup-certs
	@echo "테스트 인증서 생성 중..."
	@cd certs && bash ../generate_test_certs.sh
	@echo "테스트 인증서 생성 완료"

# 서버 실행 (프로덕션 모드 - HSM 사용)
run-server-prod:
	@echo "프로덕션 서버 시작 (HSM 사용)..."
	@read -p "HSM PIN: " pin; \
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH \
	./$(SERVER_TARGET) --hsm --hsm-pin $$pin --port 8443

# 서버 실행 (테스트 모드)
run-server: $(SERVER_TARGET)
	@echo "테스트 서버 시작..."
	@if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then \
		echo "인증서가 없습니다. 'make test-certs'를 먼저 실행하세요."; \
		exit 1; \
	fi
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH \
	./$(SERVER_TARGET) --port 8443 --key certs/server.key

# 클라이언트 실행 (프로덕션 모드 - HSM 사용)
run-client-prod:
	@echo "프로덕션 클라이언트 시작 (HSM 사용)..."
	@read -p "HSM PIN: " pin; \
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH \
	./$(CLIENT_TARGET) --host localhost --port 8443 --hsm --hsm-pin $$pin

# 클라이언트 실행 (테스트 모드)
run-client: $(CLIENT_TARGET)
	@echo "테스트 클라이언트 시작..."
	@if [ ! -f certs/client.crt ] || [ ! -f certs/client.key ]; then \
		echo "인증서가 없습니다. 'make test-certs'를 먼저 실행하세요."; \
		exit 1; \
	fi
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH \
	./$(CLIENT_TARGET) --host localhost --port 8443 --key certs/client.key

# Vault 데모 실행
run-vault-demo: $(VAULT_TARGET)
	@echo "Vault 통합 데모 시작..."
	@if [ -z "$$VAULT_TOKEN" ]; then \
		echo "VAULT_TOKEN 환경 변수를 설정하세요."; \
		echo "예: export VAULT_TOKEN=s.xxxxx"; \
		exit 1; \
	fi
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH \
	./$(VAULT_TARGET) --token $$VAULT_TOKEN --cn qtls-server.qsign.local

# Docker 컨테이너 빌드 (선택적)
docker-build:
	@echo "Docker 이미지 빌드 중..."
	docker build -t qsign/qtls-server:latest -f Dockerfile.server .
	docker build -t qsign/qtls-client:latest -f Dockerfile.client .

# Docker Compose로 전체 환경 시작
docker-up:
	@echo "Docker Compose 환경 시작..."
	docker-compose up -d

# Docker Compose 환경 중지
docker-down:
	@echo "Docker Compose 환경 중지..."
	docker-compose down

# APISIX 설정 검증
validate-apisix:
	@echo "APISIX 설정 파일 검증 중..."
	@if command -v yamllint > /dev/null; then \
		yamllint apisix_config.yaml; \
	else \
		echo "yamllint가 설치되지 않았습니다. 'pip install yamllint' 실행"; \
	fi

# APISIX에 설정 배포
deploy-apisix:
	@echo "APISIX에 Q-TLS 라우트 배포 중..."
	@if [ -z "$$APISIX_ADMIN_KEY" ]; then \
		echo "APISIX_ADMIN_KEY 환경 변수를 설정하세요."; \
		exit 1; \
	fi
	curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/qtls-secure-api \
		-H "X-API-KEY: $$APISIX_ADMIN_KEY" \
		-d @apisix_config.yaml

# 성능 테스트
benchmark: $(CLIENT_TARGET)
	@echo "성능 테스트 실행 중..."
	@echo "서버가 실행 중인지 확인하세요."
	@bash benchmark.sh

# 전체 테스트 (인증서 생성 + 빌드 + 실행)
test: test-certs test-mode
	@echo "============================================="
	@echo " QSIGN Integration 전체 테스트 준비 완료"
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

# 정리
clean:
	@echo "빌드 파일 삭제 중..."
	rm -f $(SERVER_OBJ) $(CLIENT_OBJ) $(VAULT_OBJ)
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) $(VAULT_TARGET)
	rm -f vault_*.crt vault_*.key

# 전체 정리
distclean: clean
	@echo "인증서 및 설정 파일 삭제 중..."
	rm -rf certs/
	rm -rf /tmp/qsign-test/

# 도움말
help:
	@echo "Q-TLS QSIGN Integration Makefile"
	@echo ""
	@echo "타겟:"
	@echo "  make                  - 서버와 클라이언트 빌드"
	@echo "  make all-with-vault   - Vault 통합 포함 전체 빌드"
	@echo "  make test-mode        - 테스트 모드로 빌드"
	@echo ""
	@echo "인증서:"
	@echo "  make setup-certs      - 인증서 디렉토리 생성"
	@echo "  make test-certs       - 테스트 인증서 생성"
	@echo ""
	@echo "실행:"
	@echo "  make run-server       - 서버 실행 (테스트)"
	@echo "  make run-client       - 클라이언트 실행 (테스트)"
	@echo "  make run-server-prod  - 서버 실행 (프로덕션, HSM)"
	@echo "  make run-client-prod  - 클라이언트 실행 (프로덕션, HSM)"
	@echo "  make run-vault-demo   - Vault 통합 데모"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build     - Docker 이미지 빌드"
	@echo "  make docker-up        - Docker Compose 시작"
	@echo "  make docker-down      - Docker Compose 중지"
	@echo ""
	@echo "APISIX:"
	@echo "  make validate-apisix  - APISIX 설정 검증"
	@echo "  make deploy-apisix    - APISIX에 설정 배포"
	@echo ""
	@echo "테스트:"
	@echo "  make test             - 전체 테스트 환경 준비"
	@echo "  make benchmark        - 성능 테스트"
	@echo ""
	@echo "정리:"
	@echo "  make clean            - 빌드 파일 삭제"
	@echo "  make distclean        - 전체 삭제 (인증서 포함)"
	@echo "  make help             - 이 도움말 표시"

.PHONY: all all-with-vault test-mode setup-certs test-certs \
        run-server run-client run-server-prod run-client-prod run-vault-demo \
        docker-build docker-up docker-down \
        validate-apisix deploy-apisix benchmark test clean distclean help
