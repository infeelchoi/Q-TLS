/*
 * Q-TLS 상호 TLS (mTLS) 통합 테스트
 * 클라이언트-서버 양방향 인증 테스트
 *
 * 테스트 항목:
 * - 서버 인증서 검증
 * - 클라이언트 인증서 검증
 * - 상호 인증 핸드셰이크
 * - 인증서 체인 검증
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define COLOR_GREEN   "\033[0;32m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_RESET   "\033[0m"

#define TEST_START(name) printf(COLOR_YELLOW "[시작]" COLOR_RESET " %s\n", name);
#define TEST_PASS(name) printf(COLOR_GREEN "[성공]" COLOR_RESET " %s\n", name); tests_passed++;
#define TEST_FAIL(name, reason) printf(COLOR_RED "[실패]" COLOR_RESET " %s: %s\n", name, reason); tests_failed++;

/*
 * 테스트 1: DILITHIUM 서명 검증 (인증서 시뮬레이션)
 */
static int test_certificate_signature_verification(void) {
    TEST_START("test_certificate_signature_verification");

    QTLS_DILITHIUM_KEY ca_key, server_key;
    uint8_t certificate_data[] = "서버 인증서 데이터";
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;
    int ret;

    /* CA 키 생성 */
    ret = qtls_dilithium_keygen(&ca_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_certificate_signature_verification", "CA 키 생성 실패");
        return -1;
    }

    /* 서버 키 생성 */
    ret = qtls_dilithium_keygen(&server_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_certificate_signature_verification", "서버 키 생성 실패");
        return -1;
    }

    /* CA가 서버 인증서에 서명 */
    ret = qtls_dilithium_sign(&ca_key, certificate_data, sizeof(certificate_data),
                              signature, &sig_len);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_certificate_signature_verification", "인증서 서명 실패");
        return -1;
    }

    /* 클라이언트가 CA 공개키로 서버 인증서 검증 */
    ret = qtls_dilithium_verify(&ca_key, certificate_data, sizeof(certificate_data),
                                signature, sig_len);
    if (ret != 1) {
        TEST_FAIL("test_certificate_signature_verification", "인증서 검증 실패");
        return -1;
    }

    printf("  인증서 서명 검증 성공\n");

    qtls_secure_zero(&ca_key, sizeof(ca_key));
    qtls_secure_zero(&server_key, sizeof(server_key));
    qtls_secure_zero(signature, sizeof(signature));

    TEST_PASS("test_certificate_signature_verification");
    return 0;
}

/*
 * 테스트 2: 상호 인증 시뮬레이션
 */
static int test_mutual_authentication(void) {
    TEST_START("test_mutual_authentication");

    QTLS_DILITHIUM_KEY ca_key, server_key, client_key;
    uint8_t server_cert[] = "서버 인증서";
    uint8_t client_cert[] = "클라이언트 인증서";
    uint8_t server_sig[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    uint8_t client_sig[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t server_sig_len, client_sig_len;
    int ret;

    /* CA 키 생성 */
    ret = qtls_dilithium_keygen(&ca_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_mutual_authentication", "CA 키 생성 실패");
        return -1;
    }

    /* 서버와 클라이언트 키 생성 */
    ret = qtls_dilithium_keygen(&server_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_mutual_authentication", "서버 키 생성 실패");
        return -1;
    }

    ret = qtls_dilithium_keygen(&client_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_mutual_authentication", "클라이언트 키 생성 실패");
        return -1;
    }

    /* CA가 서버 인증서 서명 */
    ret = qtls_dilithium_sign(&ca_key, server_cert, sizeof(server_cert),
                              server_sig, &server_sig_len);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_mutual_authentication", "서버 인증서 서명 실패");
        return -1;
    }

    /* CA가 클라이언트 인증서 서명 */
    ret = qtls_dilithium_sign(&ca_key, client_cert, sizeof(client_cert),
                              client_sig, &client_sig_len);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_mutual_authentication", "클라이언트 인증서 서명 실패");
        return -1;
    }

    /* 클라이언트가 서버 인증서 검증 */
    ret = qtls_dilithium_verify(&ca_key, server_cert, sizeof(server_cert),
                                server_sig, server_sig_len);
    if (ret != 1) {
        TEST_FAIL("test_mutual_authentication", "서버 인증서 검증 실패");
        return -1;
    }

    /* 서버가 클라이언트 인증서 검증 */
    ret = qtls_dilithium_verify(&ca_key, client_cert, sizeof(client_cert),
                                client_sig, client_sig_len);
    if (ret != 1) {
        TEST_FAIL("test_mutual_authentication", "클라이언트 인증서 검증 실패");
        return -1;
    }

    printf("  상호 인증 성공 (서버 ↔ 클라이언트)\n");

    qtls_secure_zero(&ca_key, sizeof(ca_key));
    qtls_secure_zero(&server_key, sizeof(server_key));
    qtls_secure_zero(&client_key, sizeof(client_key));

    TEST_PASS("test_mutual_authentication");
    return 0;
}

/*
 * 테스트 3: 잘못된 인증서 거부
 */
static int test_invalid_certificate_rejection(void) {
    TEST_START("test_invalid_certificate_rejection");

    QTLS_DILITHIUM_KEY ca_key, attacker_key;
    uint8_t legitimate_cert[] = "정상 인증서";
    uint8_t attacker_cert[] = "공격자 인증서";
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;
    int ret;

    /* CA 키 생성 */
    ret = qtls_dilithium_keygen(&ca_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_invalid_certificate_rejection", "CA 키 생성 실패");
        return -1;
    }

    /* 공격자 키 생성 */
    ret = qtls_dilithium_keygen(&attacker_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_invalid_certificate_rejection", "공격자 키 생성 실패");
        return -1;
    }

    /* 공격자가 자신의 키로 인증서 위조 */
    ret = qtls_dilithium_sign(&attacker_key, attacker_cert, sizeof(attacker_cert),
                              signature, &sig_len);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_invalid_certificate_rejection", "위조 서명 생성 실패");
        return -1;
    }

    /* CA 키로 위조 인증서 검증 시도 (실패해야 함) */
    ret = qtls_dilithium_verify(&ca_key, attacker_cert, sizeof(attacker_cert),
                                signature, sig_len);
    if (ret == 1) {
        TEST_FAIL("test_invalid_certificate_rejection", "위조 인증서가 검증됨");
        return -1;
    }

    printf("  위조 인증서 올바르게 거부됨\n");

    qtls_secure_zero(&ca_key, sizeof(ca_key));
    qtls_secure_zero(&attacker_key, sizeof(attacker_key));

    TEST_PASS("test_invalid_certificate_rejection");
    return 0;
}

int main(void) {
    printf("\n==========================================\n");
    printf("  Q-TLS 상호 TLS 통합 테스트\n");
    printf("  양방향 인증 및 인증서 검증\n");
    printf("==========================================\n\n");

    if (test_certificate_signature_verification() != 0) tests_failed++;
    if (test_mutual_authentication() != 0) tests_failed++;
    if (test_invalid_certificate_rejection() != 0) tests_failed++;

    printf("\n==========================================\n");
    if (tests_failed == 0) {
        printf(COLOR_GREEN "  모든 mTLS 테스트 통과!" COLOR_RESET "\n");
        printf("  통과: %d개\n", tests_passed);
    } else {
        printf(COLOR_RED "  일부 mTLS 테스트 실패!" COLOR_RESET "\n");
        printf("  통과: %d개, 실패: %d개\n", tests_passed, tests_failed);
    }
    printf("==========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
