# Q-TLS 키 생성 도구 Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -loqs

# HSM 지원 (Luna HSM)
HSM_ENABLED = 0
HSM_CFLAGS = -DENABLE_HSM
HSM_LDFLAGS = -L/usr/safenet/lunaclient/lib -lCryptoki2_64 -ldl

TARGETS = keygen

# HSM 지원이 활성화된 경우
ifeq ($(HSM_ENABLED), 1)
    TARGETS += keygen-hsm
endif

.PHONY: all clean install hsm

all: $(TARGETS)

# 표준 키 생성 도구 (liboqs)
keygen: keygen.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# HSM 키 생성 도구
keygen-hsm: keygen-hsm.c
	$(CC) $(CFLAGS) $(HSM_CFLAGS) -o $@ $< $(HSM_LDFLAGS)

# HSM 지원 빌드
hsm:
	$(MAKE) HSM_ENABLED=1

clean:
	rm -f keygen keygen-hsm
	rm -f *.key *.pub

install: $(TARGETS)
	install -d /usr/local/bin
	install -m 755 keygen /usr/local/bin/qtls-keygen
	@if [ -f keygen-hsm ]; then \
		install -m 755 keygen-hsm /usr/local/bin/qtls-keygen-hsm; \
	fi

uninstall:
	rm -f /usr/local/bin/qtls-keygen
	rm -f /usr/local/bin/qtls-keygen-hsm

test: keygen
	@echo "=== Kyber768 키 생성 테스트 ==="
	./keygen -t kem -a Kyber768 -p kyber_test_pub.key -s kyber_test_sec.key
	@echo ""
	@echo "=== Dilithium3 키 생성 테스트 ==="
	./keygen -t sig -a Dilithium3 -p dilithium_test_pub.key -s dilithium_test_sec.key
	@echo ""
	@echo "테스트 완료!"
	@rm -f kyber_test_*.key dilithium_test_*.key
