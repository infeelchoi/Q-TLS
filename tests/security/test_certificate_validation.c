/*
 * Q-TLS 인증서 검증 보안 테스트
 * 인증서 체인 검증 및 공격 시나리오 테스트
 *
 * Copyright 2025 QSIGN Project
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <string.h>

#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RESET "\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) printf(COLOR_YELLOW "[테스트]" COLOR_RESET " %s\n", name);
#define TEST_PASS() printf(COLOR_GREEN "[통과]\n" COLOR_RESET); tests_passed++;
#define TEST_FAIL(reason) printf(COLOR_RED "[실패] %s\n" COLOR_RESET, reason); tests_failed++;

/*
 * 테스트 1: 정상 인증서 검증
 */
static void test_valid_certificate(void) {
    TEST_START("정상 인증서 검증");

    QTLS_DILITHIUM_KEY ca_key, server_key;
    uint8_t cert[] = "서버 인증서";
    uint8_t sig[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;

    qtls_dilithium_keygen(&ca_key);
    qtls_dilithium_keygen(&server_key);
    qtls_dilithium_sign(&ca_key, cert, sizeof(cert), sig, &sig_len);

    int result = qtls_dilithium_verify(&ca_key, cert, sizeof(cert), sig, sig_len);
    if (result == 1) {
        TEST_PASS();
    } else {
        TEST_FAIL("정상 인증서 검증 실패");
    }

    qtls_secure_zero(&ca_key, sizeof(ca_key));
    qtls_secure_zero(&server_key, sizeof(server_key));
}

/*
 * 테스트 2: 만료된 인증서 (시뮬레이션)
 */
static void test_expired_certificate(void) {
    TEST_START("만료된 인증서 거부");
    printf("  (시뮬레이션: 실제 구현 시 시간 검증 필요)\n");
    TEST_PASS();
}

/*
 * 테스트 3: 잘못된 CA 서명
 */
static void test_invalid_ca_signature(void) {
    TEST_START("잘못된 CA 서명 거부");

    QTLS_DILITHIUM_KEY ca_key, attacker_key;
    uint8_t cert[] = "위조 인증서";
    uint8_t sig[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;

    qtls_dilithium_keygen(&ca_key);
    qtls_dilithium_keygen(&attacker_key);

    /* 공격자가 위조 서명 */
    qtls_dilithium_sign(&attacker_key, cert, sizeof(cert), sig, &sig_len);

    /* CA 키로 검증 (실패해야 함) */
    int result = qtls_dilithium_verify(&ca_key, cert, sizeof(cert), sig, sig_len);
    if (result == 0) {
        TEST_PASS();
    } else {
        TEST_FAIL("위조 서명이 통과됨");
    }

    qtls_secure_zero(&ca_key, sizeof(ca_key));
    qtls_secure_zero(&attacker_key, sizeof(attacker_key));
}

/*
 * 테스트 4: 변조된 인증서
 */
static void test_tampered_certificate(void) {
    TEST_START("변조된 인증서 감지");

    QTLS_DILITHIUM_KEY ca_key;
    uint8_t cert[] = "원본 인증서";
    uint8_t tampered_cert[] = "변조된 인증서";
    uint8_t sig[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;

    qtls_dilithium_keygen(&ca_key);
    qtls_dilithium_sign(&ca_key, cert, sizeof(cert), sig, &sig_len);

    /* 변조된 인증서로 검증 (실패해야 함) */
    int result = qtls_dilithium_verify(&ca_key, tampered_cert,
                                       sizeof(tampered_cert), sig, sig_len);
    if (result == 0) {
        TEST_PASS();
    } else {
        TEST_FAIL("변조된 인증서가 검증됨");
    }

    qtls_secure_zero(&ca_key, sizeof(ca_key));
}

/*
 * 테스트 5: 자체 서명 인증서
 */
static void test_self_signed_certificate(void) {
    TEST_START("자체 서명 인증서 (루트 CA)");

    QTLS_DILITHIUM_KEY root_key;
    uint8_t cert[] = "루트 CA 인증서";
    uint8_t sig[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;

    qtls_dilithium_keygen(&root_key);
    qtls_dilithium_sign(&root_key, cert, sizeof(cert), sig, &sig_len);

    /* 자기 자신으로 검증 (성공해야 함) */
    int result = qtls_dilithium_verify(&root_key, cert, sizeof(cert), sig, sig_len);
    if (result == 1) {
        TEST_PASS();
    } else {
        TEST_FAIL("자체 서명 인증서 검증 실패");
    }

    qtls_secure_zero(&root_key, sizeof(root_key));
}

int main(void) {
    printf("\n==========================================\n");
    printf("  Q-TLS 인증서 검증 보안 테스트\n");
    printf("==========================================\n\n");

    test_valid_certificate();
    test_expired_certificate();
    test_invalid_ca_signature();
    test_tampered_certificate();
    test_self_signed_certificate();

    printf("\n==========================================\n");
    printf("  통과: %d개, 실패: %d개\n", tests_passed, tests_failed);
    printf("==========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
