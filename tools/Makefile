# Q-TLS Tools Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
INSTALL_DIR = /usr/local/bin

.PHONY: all clean install uninstall

all: qtls

qtls: qtls-cli.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "✓ qtls CLI 빌드 완료"

install: qtls
	@echo "Q-TLS CLI 설치 중..."
	install -d $(INSTALL_DIR)
	install -m 755 qtls $(INSTALL_DIR)/qtls
	@if [ -d "keygen" ]; then \
		cd keygen && $(MAKE) install; \
	fi
	@if [ -d "certgen" ]; then \
		cd certgen && $(MAKE) install; \
	fi
	@echo "✓ 설치 완료"
	@echo ""
	@echo "사용법:"
	@echo "  qtls quickstart -d ./my-pki"
	@echo "  qtls keygen kyber768 -o mykey"
	@echo "  qtls certgen server -cn myserver.com -o server"

uninstall:
	rm -f $(INSTALL_DIR)/qtls
	@if [ -d "keygen" ]; then \
		cd keygen && $(MAKE) uninstall; \
	fi
	@if [ -d "certgen" ]; then \
		cd certgen && $(MAKE) uninstall; \
	fi
	@echo "✓ 제거 완료"

clean:
	rm -f qtls
	@if [ -d "keygen" ]; then \
		cd keygen && $(MAKE) clean; \
	fi
	@if [ -d "certgen" ]; then \
		cd certgen && $(MAKE) clean; \
	fi
	@if [ -d "benchmark" ]; then \
		cd benchmark && $(MAKE) clean; \
	fi

test: qtls
	@echo "=== Q-TLS CLI 테스트 ==="
	@./qtls version
	@echo ""
	@echo "✓ 테스트 완료"
