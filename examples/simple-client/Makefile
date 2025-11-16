# Q-TLS Simple Client Makefile
# 간단한 Q-TLS 클라이언트 예제 빌드 파일

# 컴파일러 설정
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lqtls -loqs -lssl -lcrypto -lpthread -lm

# 경로 설정
QTLS_INCLUDE = ../../include
QTLS_LIB = ../../build

# 소스 및 타겟
TARGET = simple_client
SOURCES = simple_client.c
OBJECTS = $(SOURCES:.c=.o)

# 기본 타겟
all: $(TARGET)

# 실행 파일 생성
$(TARGET): $(OBJECTS)
	@echo "링킹: $(TARGET)"
	$(CC) -o $@ $^ -L$(QTLS_LIB) $(LDFLAGS)
	@echo "빌드 완료: $(TARGET)"

# 오브젝트 파일 생성
%.o: %.c
	@echo "컴파일: $<"
	$(CC) $(CFLAGS) -I$(QTLS_INCLUDE) -c $< -o $@

# localhost 테스트 실행
run: $(TARGET)
	@echo "클라이언트 시작 중 (localhost:8443)..."
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH ./$(TARGET) localhost 8443

# 사용자 지정 서버 테스트
test: $(TARGET)
	@echo "사용법: make test HOST=example.com PORT=8443"
	@if [ -z "$(HOST)" ]; then \
		echo "HOST 변수를 설정하세요: make test HOST=example.com"; \
		exit 1; \
	fi
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH ./$(TARGET) $(HOST) $(if $(PORT),$(PORT),8443)

# 정리
clean:
	@echo "빌드 파일 삭제 중..."
	rm -f $(OBJECTS) $(TARGET)

# 도움말
help:
	@echo "Q-TLS Simple Client Makefile"
	@echo ""
	@echo "사용 가능한 타겟:"
	@echo "  make          - 클라이언트 빌드"
	@echo "  make run      - localhost:8443에 연결"
	@echo "  make test HOST=example.com PORT=8443 - 지정된 서버에 연결"
	@echo "  make clean    - 빌드 파일 삭제"
	@echo "  make help     - 이 도움말 표시"
	@echo ""
	@echo "수동 실행 예시:"
	@echo "  ./$(TARGET) localhost 8443"
	@echo "  ./$(TARGET) example.com 9443 \"Hello, World!\" -verify"

.PHONY: all run test clean help
