# Q-TLS 단위 테스트 Makefile
# KYBER1024, DILITHIUM3, 핸드셰이크, 세션 관리 테스트 빌드

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -I../../include
LDFLAGS = -L../../build -lqtls -loqs -lcrypto -lssl -lpthread

# 테스트 실행 파일
TESTS = test_kyber test_dilithium test_handshake test_session

# 기본 타겟: 모든 테스트 빌드
all: $(TESTS)

# KYBER 테스트
test_kyber: test_kyber.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# DILITHIUM 테스트
test_dilithium: test_dilithium.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# 핸드셰이크 테스트
test_handshake: test_handshake.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# 세션 관리 테스트
test_session: test_session.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# 모든 테스트 실행
test: $(TESTS)
	@echo ""
	@echo "=========================================="
	@echo "  Q-TLS 단위 테스트 실행"
	@echo "=========================================="
	@echo ""
	@for test in $(TESTS); do \
		echo "실행 중: $$test"; \
		LD_LIBRARY_PATH=../../build ./$$test || exit 1; \
	done
	@echo ""
	@echo "=========================================="
	@echo "  모든 단위 테스트 완료!"
	@echo "=========================================="
	@echo ""

# 개별 테스트 실행
run-kyber: test_kyber
	LD_LIBRARY_PATH=../../build ./test_kyber

run-dilithium: test_dilithium
	LD_LIBRARY_PATH=../../build ./test_dilithium

run-handshake: test_handshake
	LD_LIBRARY_PATH=../../build ./test_handshake

run-session: test_session
	LD_LIBRARY_PATH=../../build ./test_session

# 정리
clean:
	rm -f $(TESTS) *.o

.PHONY: all test clean run-kyber run-dilithium run-handshake run-session
