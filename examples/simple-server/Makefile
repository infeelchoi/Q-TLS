# Q-TLS Simple Server Makefile
# 간단한 Q-TLS 서버 예제 빌드 파일

# 컴파일러 설정
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lqtls -loqs -lssl -lcrypto -lpthread -lm

# 경로 설정
QTLS_INCLUDE = ../../include
QTLS_LIB = ../../build

# 소스 및 타겟
TARGET = simple_server
SOURCES = simple_server.c
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

# 실행
run: $(TARGET)
	@echo "서버 시작 중..."
	@if [ ! -f server.crt ] || [ ! -f server.key ]; then \
		echo "인증서가 없습니다. generate_certs.sh를 먼저 실행하세요."; \
		exit 1; \
	fi
	LD_LIBRARY_PATH=$(QTLS_LIB):$$LD_LIBRARY_PATH ./$(TARGET)

# 인증서 생성
certs:
	@echo "서버 인증서 생성 중..."
	bash generate_certs.sh

# 정리
clean:
	@echo "빌드 파일 삭제 중..."
	rm -f $(OBJECTS) $(TARGET)

# 인증서 포함 전체 정리
distclean: clean
	@echo "인증서 파일 삭제 중..."
	rm -f server.crt server.key server.csr

# 도움말
help:
	@echo "Q-TLS Simple Server Makefile"
	@echo ""
	@echo "사용 가능한 타겟:"
	@echo "  make          - 서버 빌드"
	@echo "  make run      - 서버 실행"
	@echo "  make certs    - 서버 인증서 생성"
	@echo "  make clean    - 빌드 파일 삭제"
	@echo "  make distclean - 빌드 파일 및 인증서 삭제"
	@echo "  make help     - 이 도움말 표시"

.PHONY: all run certs clean distclean help
