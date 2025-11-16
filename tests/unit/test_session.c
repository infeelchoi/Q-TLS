/*
 * Q-TLS 세션 관리 단위 테스트
 * 세션 키, 보안 메모리 관리 테스트
 *
 * 테스트 항목:
 * - 세션 키 생성 및 관리
 * - 보안 메모리 제로화
 * - 키 회전 (rotation)
 * - 메모리 누수 방지
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

/* 테스트 결과 카운터 */
static int tests_passed = 0;
static int tests_failed = 0;

/* 색상 출력용 ANSI 코드 */
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_RESET   "\033[0m"

/* 테스트 매크로 */
#define TEST_START(name) \
    printf(COLOR_YELLOW "[ RUN      ]" COLOR_RESET " %s\n", name);

#define TEST_PASS(name) \
    printf(COLOR_GREEN "[       OK ]" COLOR_RESET " %s\n", name); \
    tests_passed++;

#define ASSERT_EQ(expected, actual, msg) \
    if ((expected) != (actual)) { \
        printf("  ASSERTION FAILED: %s (expected=%d, actual=%d)\n", \
               msg, expected, actual); \
        return -1; \
    }

#define ASSERT_TRUE(condition, msg) \
    if (!(condition)) { \
        printf("  ASSERTION FAILED: %s\n", msg); \
        return -1; \
    }

/*
 * 테스트 1: 보안 메모리 제로화
 * qtls_secure_zero가 메모리를 안전하게 지우는지 확인
 */
static int test_secure_zero(void) {
    TEST_START("test_secure_zero");

    uint8_t buffer[128];

    /* 버퍼를 랜덤 데이터로 채움 */
    RAND_bytes(buffer, sizeof(buffer));

    /* 데이터가 실제로 있는지 확인 */
    int has_data = 0;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            has_data = 1;
            break;
        }
    }
    ASSERT_TRUE(has_data, "Buffer should have data before zeroing");

    /* 보안 제로화 실행 */
    qtls_secure_zero(buffer, sizeof(buffer));

    /* 모든 바이트가 0인지 확인 */
    int all_zeros = 1;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zeros, "Buffer should be all zeros after secure_zero");

    TEST_PASS("test_secure_zero");
    return 0;
}

/*
 * 테스트 2: NULL 포인터 안전성
 * qtls_secure_zero가 NULL 포인터를 안전하게 처리하는지 확인
 */
static int test_secure_zero_null(void) {
    TEST_START("test_secure_zero_null");

    /* NULL 포인터로 호출해도 크래시하지 않아야 함 */
    qtls_secure_zero(NULL, 100);

    /* 0 길이로 호출해도 안전해야 함 */
    uint8_t buffer[10];
    qtls_secure_zero(buffer, 0);

    TEST_PASS("test_secure_zero_null");
    return 0;
}

/*
 * 테스트 3: 세션 키 구조체 제로화
 * 민감한 키 데이터가 완전히 지워지는지 확인
 */
static int test_session_keys_cleanup(void) {
    TEST_START("test_session_keys_cleanup");

    QTLS_SESSION_KEYS keys;

    /* 키 데이터로 채움 */
    RAND_bytes(keys.client_write_key, sizeof(keys.client_write_key));
    RAND_bytes(keys.server_write_key, sizeof(keys.server_write_key));
    RAND_bytes(keys.client_write_iv, sizeof(keys.client_write_iv));
    RAND_bytes(keys.server_write_iv, sizeof(keys.server_write_iv));

    /* 보안 제로화 */
    qtls_secure_zero(&keys, sizeof(keys));

    /* 모든 필드가 0인지 확인 */
    int all_zeros = 1;
    uint8_t *ptr = (uint8_t*)&keys;
    for (size_t i = 0; i < sizeof(keys); i++) {
        if (ptr[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zeros, "Session keys should be completely zeroed");

    TEST_PASS("test_session_keys_cleanup");
    return 0;
}

/*
 * 테스트 4: KYBER 키 구조체 제로화
 * PQC 키가 안전하게 제거되는지 확인
 */
static int test_kyber_key_cleanup(void) {
    TEST_START("test_kyber_key_cleanup");

    QTLS_KYBER_KEY key;
    int ret;

    /* 실제 키 생성 */
    ret = qtls_kyber_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* 키 데이터 확인 */
    int has_data = 0;
    for (size_t i = 0; i < QTLS_KYBER1024_PUBLIC_KEY_BYTES; i++) {
        if (key.public_key[i] != 0) {
            has_data = 1;
            break;
        }
    }
    ASSERT_TRUE(has_data, "Key should have data");

    /* 보안 제로화 */
    qtls_secure_zero(&key, sizeof(key));

    /* 전체 구조체가 0인지 확인 */
    int all_zeros = 1;
    uint8_t *ptr = (uint8_t*)&key;
    for (size_t i = 0; i < sizeof(key); i++) {
        if (ptr[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zeros, "KYBER key should be completely zeroed");

    TEST_PASS("test_kyber_key_cleanup");
    return 0;
}

/*
 * 테스트 5: DILITHIUM 키 구조체 제로화
 * 서명 키가 안전하게 제거되는지 확인
 */
static int test_dilithium_key_cleanup(void) {
    TEST_START("test_dilithium_key_cleanup");

    QTLS_DILITHIUM_KEY key;
    int ret;

    /* 실제 키 생성 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* 키 데이터 확인 */
    int has_data = 0;
    for (size_t i = 0; i < QTLS_DILITHIUM3_SECRET_KEY_BYTES; i++) {
        if (key.secret_key[i] != 0) {
            has_data = 1;
            break;
        }
    }
    ASSERT_TRUE(has_data, "Key should have data");

    /* 보안 제로화 */
    qtls_secure_zero(&key, sizeof(key));

    /* 전체 구조체가 0인지 확인 */
    int all_zeros = 1;
    uint8_t *ptr = (uint8_t*)&key;
    for (size_t i = 0; i < sizeof(key); i++) {
        if (ptr[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zeros, "DILITHIUM key should be completely zeroed");

    TEST_PASS("test_dilithium_key_cleanup");
    return 0;
}

/*
 * 테스트 6: 하이브리드 시크릿 제로화
 * 마스터 시크릿이 안전하게 제거되는지 확인
 */
static int test_hybrid_secret_cleanup(void) {
    TEST_START("test_hybrid_secret_cleanup");

    QTLS_HYBRID_SECRET secret;
    int ret;

    /* 시크릿 데이터 생성 */
    RAND_bytes(secret.classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    RAND_bytes(secret.pqc_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    RAND_bytes(secret.client_random, QTLS_MAX_RANDOM_LEN);
    RAND_bytes(secret.server_random, QTLS_MAX_RANDOM_LEN);

    ret = qtls_derive_master_secret(&secret);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Master secret derivation should succeed");

    /* 보안 제로화 */
    qtls_secure_zero(&secret, sizeof(secret));

    /* 전체 구조체가 0인지 확인 */
    int all_zeros = 1;
    uint8_t *ptr = (uint8_t*)&secret;
    for (size_t i = 0; i < sizeof(secret); i++) {
        if (ptr[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zeros, "Hybrid secret should be completely zeroed");

    TEST_PASS("test_hybrid_secret_cleanup");
    return 0;
}

/*
 * 테스트 7: 세션 키 독립성
 * 각 세션의 키가 독립적인지 확인
 */
static int test_session_key_independence(void) {
    TEST_START("test_session_key_independence");

    QTLS_HYBRID_SECRET secret1, secret2;
    QTLS_SESSION_KEYS keys1, keys2;
    int ret;

    /* 첫 번째 세션 */
    RAND_bytes(secret1.classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    RAND_bytes(secret1.pqc_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    RAND_bytes(secret1.client_random, QTLS_MAX_RANDOM_LEN);
    RAND_bytes(secret1.server_random, QTLS_MAX_RANDOM_LEN);
    ret = qtls_derive_master_secret(&secret1);
    ASSERT_EQ(QTLS_SUCCESS, ret, "First master secret should succeed");
    ret = qtls_derive_session_keys(&secret1, &keys1);
    ASSERT_EQ(QTLS_SUCCESS, ret, "First session keys should succeed");

    /* 두 번째 세션 */
    RAND_bytes(secret2.classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    RAND_bytes(secret2.pqc_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    RAND_bytes(secret2.client_random, QTLS_MAX_RANDOM_LEN);
    RAND_bytes(secret2.server_random, QTLS_MAX_RANDOM_LEN);
    ret = qtls_derive_master_secret(&secret2);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Second master secret should succeed");
    ret = qtls_derive_session_keys(&secret2, &keys2);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Second session keys should succeed");

    /* 두 세션의 키가 달라야 함 */
    ASSERT_TRUE(memcmp(&keys1, &keys2, sizeof(keys1)) != 0,
                "Different sessions should have different keys");

    qtls_secure_zero(&secret1, sizeof(secret1));
    qtls_secure_zero(&secret2, sizeof(secret2));
    qtls_secure_zero(&keys1, sizeof(keys1));
    qtls_secure_zero(&keys2, sizeof(keys2));

    TEST_PASS("test_session_key_independence");
    return 0;
}

/*
 * 테스트 8: 버전 문자열 확인
 * 라이브러리 버전이 올바르게 반환되는지 확인
 */
static int test_version_string(void) {
    TEST_START("test_version_string");

    const char *version = qtls_version();

    ASSERT_TRUE(version != NULL, "Version string should not be NULL");
    ASSERT_TRUE(strlen(version) > 0, "Version string should not be empty");
    ASSERT_TRUE(strcmp(version, QTLS_VERSION_STRING) == 0,
                "Version string should match");

    printf("  Q-TLS Version: %s\n", version);

    TEST_PASS("test_version_string");
    return 0;
}

/*
 * 테스트 9: 에러 문자열 확인
 * 모든 에러 코드에 대한 설명이 있는지 확인
 */
static int test_error_strings(void) {
    TEST_START("test_error_strings");

    const int error_codes[] = {
        QTLS_SUCCESS,
        QTLS_ERROR_NULL_POINTER,
        QTLS_ERROR_INVALID_ARGUMENT,
        QTLS_ERROR_OUT_OF_MEMORY,
        QTLS_ERROR_CRYPTO_INIT,
        QTLS_ERROR_KEY_GENERATION,
        QTLS_ERROR_ENCAPSULATION,
        QTLS_ERROR_DECAPSULATION,
        QTLS_ERROR_SIGNATURE,
        QTLS_ERROR_VERIFICATION,
        QTLS_ERROR_KEY_DERIVATION,
        QTLS_ERROR_HANDSHAKE_FAILED,
        QTLS_ERROR_HSM_NOT_AVAILABLE
    };

    for (size_t i = 0; i < sizeof(error_codes)/sizeof(error_codes[0]); i++) {
        const char *error_str = qtls_get_error_string(error_codes[i]);
        ASSERT_TRUE(error_str != NULL, "Error string should not be NULL");
        ASSERT_TRUE(strlen(error_str) > 0, "Error string should not be empty");
    }

    TEST_PASS("test_error_strings");
    return 0;
}

/*
 * 메인 테스트 실행 함수
 */
int main(void) {
    printf("\n");
    printf("==========================================\n");
    printf("  Q-TLS 세션 관리 단위 테스트\n");
    printf("  보안 메모리 및 키 관리 검증\n");
    printf("==========================================\n\n");

    /* 모든 테스트 실행 */
    if (test_secure_zero() != 0) tests_failed++;
    if (test_secure_zero_null() != 0) tests_failed++;
    if (test_session_keys_cleanup() != 0) tests_failed++;
    if (test_kyber_key_cleanup() != 0) tests_failed++;
    if (test_dilithium_key_cleanup() != 0) tests_failed++;
    if (test_hybrid_secret_cleanup() != 0) tests_failed++;
    if (test_session_key_independence() != 0) tests_failed++;
    if (test_version_string() != 0) tests_failed++;
    if (test_error_strings() != 0) tests_failed++;

    /* 테스트 결과 요약 */
    printf("\n==========================================\n");
    if (tests_failed == 0) {
        printf(COLOR_GREEN "  모든 테스트 통과!" COLOR_RESET "\n");
        printf("  통과: %d개\n", tests_passed);
    } else {
        printf(COLOR_RED "  일부 테스트 실패!" COLOR_RESET "\n");
        printf("  통과: %d개, 실패: %d개\n", tests_passed, tests_failed);
    }
    printf("==========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
