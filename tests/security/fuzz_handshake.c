/*
 * Q-TLS 핸드셰이크 퍼징 테스트
 * 랜덤 입력으로 견고성 검증
 *
 * Copyright 2025 QSIGN Project
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FUZZ_ITERATIONS 1000
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RESET "\033[0m"

static int crashes = 0;
static int errors_handled = 0;

/*
 * 퍼즈 1: 랜덤 KYBER 암호문
 */
static void fuzz_kyber_ciphertext(void) {
    printf(COLOR_YELLOW "[퍼징]" COLOR_RESET " KYBER 랜덤 암호문 처리\n");

    QTLS_KYBER_KEY key;
    qtls_kyber_keygen(&key);

    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        /* 랜덤 암호문 생성 */
        for (int j = 0; j < QTLS_KYBER1024_CIPHERTEXT_BYTES; j++) {
            key.ciphertext[j] = (uint8_t)rand();
        }

        /* 역캡슐화 시도 (크래시하지 않아야 함) */
        int ret = qtls_kyber_decapsulate(&key);
        if (ret != QTLS_SUCCESS) {
            errors_handled++;
        }
    }

    printf("  처리됨: %d개 입력, 에러 처리: %d개\n",
           FUZZ_ITERATIONS, errors_handled);

    qtls_secure_zero(&key, sizeof(key));
}

/*
 * 퍼즈 2: 랜덤 DILITHIUM 서명
 */
static void fuzz_dilithium_signature(void) {
    printf(COLOR_YELLOW "\n[퍼징]" COLOR_RESET " DILITHIUM 랜덤 서명 검증\n");

    QTLS_DILITHIUM_KEY key;
    qtls_dilithium_keygen(&key);

    uint8_t message[100] = "테스트 메시지";
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    int handled = 0;

    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        /* 랜덤 서명 생성 */
        for (int j = 0; j < QTLS_DILITHIUM3_SIGNATURE_BYTES; j++) {
            signature[j] = (uint8_t)rand();
        }

        /* 검증 시도 (크래시하지 않아야 함) */
        int ret = qtls_dilithium_verify(&key, message, sizeof(message),
                                        signature, sizeof(signature));
        if (ret == 0 || ret < 0) {
            handled++;
        }
    }

    printf("  처리됨: %d개 입력, 올바르게 거부: %d개\n",
           FUZZ_ITERATIONS, handled);

    qtls_secure_zero(&key, sizeof(key));
}

/*
 * 퍼즈 3: 랜덤 공유 비밀
 */
static void fuzz_shared_secrets(void) {
    printf(COLOR_YELLOW "\n[퍼징]" COLOR_RESET " 랜덤 공유 비밀 키 유도\n");

    QTLS_HYBRID_SECRET secret;
    int handled = 0;

    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        /* 랜덤 시크릿 데이터 */
        for (int j = 0; j < QTLS_ECDHE_P384_SHARED_SECRET_BYTES; j++) {
            secret.classical_secret[j] = (uint8_t)rand();
        }
        for (int j = 0; j < QTLS_KYBER1024_SHARED_SECRET_BYTES; j++) {
            secret.pqc_secret[j] = (uint8_t)rand();
        }
        for (int j = 0; j < QTLS_MAX_RANDOM_LEN; j++) {
            secret.client_random[j] = (uint8_t)rand();
            secret.server_random[j] = (uint8_t)rand();
        }

        /* 키 유도 시도 (크래시하지 않아야 함) */
        int ret = qtls_derive_master_secret(&secret);
        if (ret == QTLS_SUCCESS) {
            handled++;
        }

        qtls_secure_zero(&secret, sizeof(secret));
    }

    printf("  처리됨: %d개 입력, 성공: %d개\n",
           FUZZ_ITERATIONS, handled);
}

int main(void) {
    printf("\n==========================================\n");
    printf("  Q-TLS 핸드셰이크 퍼징 테스트\n");
    printf("  랜덤 입력 견고성 검증\n");
    printf("==========================================\n\n");

    srand(time(NULL));

    fuzz_kyber_ciphertext();
    fuzz_dilithium_signature();
    fuzz_shared_secrets();

    printf("\n==========================================\n");
    if (crashes == 0) {
        printf(COLOR_GREEN "  퍼징 완료: 크래시 없음!\n" COLOR_RESET);
    }
    printf("==========================================\n\n");

    return 0;
}
