# Q-TLS 통합 테스트 Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -I../../include
LDFLAGS = -L../../build -lqtls -loqs -lcrypto -lssl -lpthread

TESTS = test_server_client test_mutual_tls test_hsm_integration test_qsign_integration

all: $(TESTS)

test_server_client: test_server_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_mutual_tls: test_mutual_tls.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_hsm_integration: test_hsm_integration.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_qsign_integration: test_qsign_integration.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: $(TESTS)
	@echo ""
	@echo "=========================================="
	@echo "  Q-TLS 통합 테스트 실행"
	@echo "=========================================="
	@echo ""
	@for test in $(TESTS); do \
		echo "실행 중: $$test"; \
		LD_LIBRARY_PATH=../../build ./$$test || exit 1; \
	done

clean:
	rm -f $(TESTS) *.o

.PHONY: all test clean
