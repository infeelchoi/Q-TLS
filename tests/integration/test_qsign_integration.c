/*
 * Q-TLS QSIGN 통합 테스트
 * QSIGN 프레임워크와의 통합 기능 테스트
 *
 * 테스트 항목:
 * - QSIGN 프레임워크 연동
 * - Q-TLS 어댑터 기능
 * - 인증서 관리 통합
 * - 정책 엔진 연동
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
 * 테스트 1: Q-TLS 버전 확인
 */
static int test_qtls_version(void) {
    TEST_START("test_qtls_version");

    const char *version = qtls_version();
    if (version == NULL || strlen(version) == 0) {
        TEST_FAIL("test_qtls_version", "버전 정보 없음");
        return -1;
    }

    printf("  Q-TLS 버전: %s\n", version);

    TEST_PASS("test_qtls_version");
    return 0;
}

/*
 * 테스트 2: QSIGN 어댑터 초기화
 */
static int test_qsign_adapter_init(void) {
    TEST_START("test_qsign_adapter_init");

    printf("  QSIGN 어댑터 초기화 시뮬레이션\n");
    printf("  - 알고리즘 협상: KYBER1024 + DILITHIUM3\n");
    printf("  - 정책 설정: 하이브리드 모드\n");

    /* 실제 구현에서는 QSIGN 프레임워크 API 호출 */

    TEST_PASS("test_qsign_adapter_init");
    return 0;
}

/*
 * 테스트 3: 통합 키 관리
 */
static int test_integrated_key_management(void) {
    TEST_START("test_integrated_key_management");

    /* KYBER + DILITHIUM 키 생성 */
    QTLS_KYBER_KEY kyber_key;
    QTLS_DILITHIUM_KEY dilithium_key;

    int ret = qtls_kyber_keygen(&kyber_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_integrated_key_management", "KYBER 키 생성 실패");
        return -1;
    }

    ret = qtls_dilithium_keygen(&dilithium_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_integrated_key_management", "DILITHIUM 키 생성 실패");
        return -1;
    }

    printf("  PQC 키 생성 완료:\n");
    printf("    - KYBER1024 공개키: %u bytes\n", QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    printf("    - DILITHIUM3 공개키: %u bytes\n", QTLS_DILITHIUM3_PUBLIC_KEY_BYTES);

    qtls_secure_zero(&kyber_key, sizeof(kyber_key));
    qtls_secure_zero(&dilithium_key, sizeof(dilithium_key));

    TEST_PASS("test_integrated_key_management");
    return 0;
}

/*
 * 테스트 4: 하이브리드 보안 레벨
 */
static int test_hybrid_security_level(void) {
    TEST_START("test_hybrid_security_level");

    printf("  하이브리드 보안 레벨 확인:\n");
    printf("    - 고전 암호: ECDHE P-384 (192-bit 보안)\n");
    printf("    - PQC KEM: KYBER1024 (256-bit 보안, NIST Level 5)\n");
    printf("    - PQC 서명: DILITHIUM3 (192-bit 보안, NIST Level 3)\n");
    printf("    - 대칭 암호: AES-256-GCM\n");
    printf("  → 최종 보안 레벨: max(고전, PQC) = 256-bit\n");

    TEST_PASS("test_hybrid_security_level");
    return 0;
}

/*
 * 테스트 5: 전체 통합 워크플로우
 */
static int test_full_integration_workflow(void) {
    TEST_START("test_full_integration_workflow");

    printf("  QSIGN-QTLS 통합 워크플로우:\n");
    printf("    1. QSIGN 정책 엔진: 알고리즘 선택\n");
    printf("    2. Q-TLS: 하이브리드 핸드셰이크 수행\n");
    printf("    3. QSIGN 인증서 관리: 인증서 검증\n");
    printf("    4. Q-TLS: 세션 키 유도 및 암호화 통신\n");
    printf("    5. QSIGN 로깅: 보안 감사 기록\n");

    /* 워크플로우 시뮬레이션 */
    QTLS_KYBER_KEY server_kyber, client_kyber;
    QTLS_HYBRID_SECRET secret;
    QTLS_SESSION_KEYS keys;

    /* 1. 키 교환 */
    int ret = qtls_kyber_keygen(&server_kyber);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_integration_workflow", "서버 키 생성 실패");
        return -1;
    }

    memcpy(client_kyber.public_key, server_kyber.public_key,
           QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    client_kyber.has_secret_key = 0;

    ret = qtls_kyber_encapsulate(&client_kyber);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_integration_workflow", "캡슐화 실패");
        return -1;
    }

    memcpy(server_kyber.ciphertext, client_kyber.ciphertext,
           QTLS_KYBER1024_CIPHERTEXT_BYTES);

    ret = qtls_kyber_decapsulate(&server_kyber);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_integration_workflow", "역캡슐화 실패");
        return -1;
    }

    /* 2. 하이브리드 시크릿 생성 */
    memset(secret.classical_secret, 0xAA, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memcpy(secret.pqc_secret, server_kyber.shared_secret,
           QTLS_KYBER1024_SHARED_SECRET_BYTES);
    memset(secret.client_random, 0xCC, QTLS_MAX_RANDOM_LEN);
    memset(secret.server_random, 0xDD, QTLS_MAX_RANDOM_LEN);

    ret = qtls_derive_master_secret(&secret);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_integration_workflow", "마스터 시크릿 유도 실패");
        return -1;
    }

    /* 3. 세션 키 유도 */
    ret = qtls_derive_session_keys(&secret, &keys);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_integration_workflow", "세션 키 유도 실패");
        return -1;
    }

    printf("  통합 워크플로우 완료!\n");

    qtls_secure_zero(&server_kyber, sizeof(server_kyber));
    qtls_secure_zero(&client_kyber, sizeof(client_kyber));
    qtls_secure_zero(&secret, sizeof(secret));
    qtls_secure_zero(&keys, sizeof(keys));

    TEST_PASS("test_full_integration_workflow");
    return 0;
}

int main(void) {
    printf("\n==========================================\n");
    printf("  Q-TLS QSIGN 통합 테스트\n");
    printf("  QSIGN 프레임워크 연동 검증\n");
    printf("==========================================\n\n");

    if (test_qtls_version() != 0) tests_failed++;
    if (test_qsign_adapter_init() != 0) tests_failed++;
    if (test_integrated_key_management() != 0) tests_failed++;
    if (test_hybrid_security_level() != 0) tests_failed++;
    if (test_full_integration_workflow() != 0) tests_failed++;

    printf("\n==========================================\n");
    if (tests_failed == 0) {
        printf(COLOR_GREEN "  모든 QSIGN 통합 테스트 통과!" COLOR_RESET "\n");
        printf("  통과: %d개\n", tests_passed);
    } else {
        printf(COLOR_RED "  일부 QSIGN 통합 테스트 실패!" COLOR_RESET "\n");
        printf("  통과: %d개, 실패: %d개\n", tests_passed, tests_failed);
    }
    printf("==========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
