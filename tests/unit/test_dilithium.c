/*
 * Q-TLS DILITHIUM3 단위 테스트
 * DILITHIUM3 (ML-DSA-65) 전자서명 알고리즘 테스트
 *
 * 테스트 항목:
 * - 키 생성 (keygen)
 * - 서명 생성 (sign)
 * - 서명 검증 (verify)
 * - 잘못된 서명 거부
 * - 에러 처리
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

#define TEST_FAIL(name, reason) \
    printf(COLOR_RED "[  FAILED  ]" COLOR_RESET " %s: %s\n", name, reason); \
    tests_failed++;

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
 * 테스트 1: DILITHIUM3 키 생성
 * 공개키와 비밀키가 올바르게 생성되는지 확인
 */
static int test_dilithium_keygen(void) {
    TEST_START("test_dilithium_keygen");

    QTLS_DILITHIUM_KEY key;
    int ret;

    /* 키 생성 실행 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "qtls_dilithium_keygen should succeed");

    /* 비밀키 플래그 확인 */
    ASSERT_TRUE(key.has_secret_key == 1, "Should have secret key");

    /* 공개키가 실제로 생성되었는지 확인 */
    int all_zeros = 1;
    for (int i = 0; i < QTLS_DILITHIUM3_PUBLIC_KEY_BYTES; i++) {
        if (key.public_key[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Public key should not be all zeros");

    /* 키 정리 */
    qtls_secure_zero(&key, sizeof(key));

    TEST_PASS("test_dilithium_keygen");
    return 0;
}

/*
 * 테스트 2: DILITHIUM3 서명 생성
 * 메시지에 대한 서명이 올바르게 생성되는지 확인
 */
static int test_dilithium_sign(void) {
    TEST_START("test_dilithium_sign");

    QTLS_DILITHIUM_KEY key;
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len = 0;
    const uint8_t message[] = "Q-TLS 테스트 메시지";
    int ret;

    /* 키 생성 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* 서명 생성 */
    ret = qtls_dilithium_sign(&key, message, sizeof(message),
                              signature, &sig_len);
    ASSERT_EQ(QTLS_SUCCESS, ret, "qtls_dilithium_sign should succeed");

    /* 서명 길이 확인 */
    ASSERT_TRUE(sig_len > 0 && sig_len <= QTLS_DILITHIUM3_SIGNATURE_BYTES,
                "Signature length should be valid");

    /* 서명 데이터 확인 */
    int all_zeros = 1;
    for (size_t i = 0; i < sig_len; i++) {
        if (signature[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Signature should not be all zeros");

    qtls_secure_zero(&key, sizeof(key));
    qtls_secure_zero(signature, sizeof(signature));

    TEST_PASS("test_dilithium_sign");
    return 0;
}

/*
 * 테스트 3: DILITHIUM3 서명 검증
 * 올바른 서명이 정상적으로 검증되는지 확인
 */
static int test_dilithium_verify(void) {
    TEST_START("test_dilithium_verify");

    QTLS_DILITHIUM_KEY key;
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len = 0;
    const uint8_t message[] = "양자내성 전자서명 테스트";
    int ret;

    /* 키 생성 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* 서명 생성 */
    ret = qtls_dilithium_sign(&key, message, sizeof(message),
                              signature, &sig_len);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Signature generation should succeed");

    /* 서명 검증 (같은 키로) */
    ret = qtls_dilithium_verify(&key, message, sizeof(message),
                                signature, sig_len);
    ASSERT_EQ(1, ret, "Valid signature should verify successfully");

    qtls_secure_zero(&key, sizeof(key));
    qtls_secure_zero(signature, sizeof(signature));

    TEST_PASS("test_dilithium_verify");
    return 0;
}

/*
 * 테스트 4: 잘못된 서명 거부
 * 변조된 서명이 올바르게 거부되는지 확인
 */
static int test_dilithium_invalid_signature(void) {
    TEST_START("test_dilithium_invalid_signature");

    QTLS_DILITHIUM_KEY key;
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len = 0;
    const uint8_t message[] = "원본 메시지";
    int ret;

    /* 키 생성 및 서명 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    ret = qtls_dilithium_sign(&key, message, sizeof(message),
                              signature, &sig_len);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Signature generation should succeed");

    /* 서명 변조 (첫 바이트 변경) */
    signature[0] ^= 0xFF;

    /* 변조된 서명 검증 시도 (실패해야 함) */
    ret = qtls_dilithium_verify(&key, message, sizeof(message),
                                signature, sig_len);
    ASSERT_EQ(0, ret, "Invalid signature should be rejected");

    qtls_secure_zero(&key, sizeof(key));
    qtls_secure_zero(signature, sizeof(signature));

    TEST_PASS("test_dilithium_invalid_signature");
    return 0;
}

/*
 * 테스트 5: 메시지 변조 감지
 * 메시지가 변경되면 서명 검증이 실패하는지 확인
 */
static int test_dilithium_message_tampering(void) {
    TEST_START("test_dilithium_message_tampering");

    QTLS_DILITHIUM_KEY key;
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len = 0;
    const uint8_t original_msg[] = "원본 메시지";
    const uint8_t tampered_msg[] = "변조된 메시지";
    int ret;

    /* 키 생성 및 원본 메시지 서명 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    ret = qtls_dilithium_sign(&key, original_msg, sizeof(original_msg),
                              signature, &sig_len);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Signature generation should succeed");

    /* 변조된 메시지로 검증 시도 (실패해야 함) */
    ret = qtls_dilithium_verify(&key, tampered_msg, sizeof(tampered_msg),
                                signature, sig_len);
    ASSERT_EQ(0, ret, "Signature should fail for tampered message");

    qtls_secure_zero(&key, sizeof(key));
    qtls_secure_zero(signature, sizeof(signature));

    TEST_PASS("test_dilithium_message_tampering");
    return 0;
}

/*
 * 테스트 6: NULL 포인터 에러 처리
 * NULL 입력에 대해 적절한 에러를 반환하는지 확인
 */
static int test_dilithium_null_pointer(void) {
    TEST_START("test_dilithium_null_pointer");

    QTLS_DILITHIUM_KEY key;
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len = 0;
    const uint8_t message[] = "test";
    int ret;

    /* 키 생성 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* NULL 포인터 테스트 */
    ret = qtls_dilithium_keygen(NULL);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret, "NULL key should return error");

    ret = qtls_dilithium_sign(NULL, message, sizeof(message),
                              signature, &sig_len);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret, "NULL key should return error");

    ret = qtls_dilithium_sign(&key, NULL, sizeof(message),
                              signature, &sig_len);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret, "NULL message should return error");

    ret = qtls_dilithium_verify(NULL, message, sizeof(message),
                                signature, sig_len);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret, "NULL key should return error");

    qtls_secure_zero(&key, sizeof(key));

    TEST_PASS("test_dilithium_null_pointer");
    return 0;
}

/*
 * 테스트 7: 빈 메시지 처리
 * 빈 메시지에 대한 에러 처리 확인
 */
static int test_dilithium_empty_message(void) {
    TEST_START("test_dilithium_empty_message");

    QTLS_DILITHIUM_KEY key;
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len = 0;
    const uint8_t message[] = "test";
    int ret;

    /* 키 생성 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* 빈 메시지로 서명 시도 */
    ret = qtls_dilithium_sign(&key, message, 0, signature, &sig_len);
    ASSERT_EQ(QTLS_ERROR_INVALID_ARGUMENT, ret,
              "Empty message should return error");

    qtls_secure_zero(&key, sizeof(key));

    TEST_PASS("test_dilithium_empty_message");
    return 0;
}

/*
 * 테스트 8: 여러 번 서명 생성 (안정성 테스트)
 * 같은 키로 여러 메시지를 서명해도 문제없는지 확인
 */
static int test_dilithium_multiple_signatures(void) {
    TEST_START("test_dilithium_multiple_signatures");

    QTLS_DILITHIUM_KEY key;
    uint8_t signatures[3][QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_lens[3];
    const uint8_t messages[3][32] = {
        "첫 번째 메시지",
        "두 번째 메시지",
        "세 번째 메시지"
    };
    int ret;

    /* 키 생성 */
    ret = qtls_dilithium_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* 3개의 메시지 서명 */
    for (int i = 0; i < 3; i++) {
        ret = qtls_dilithium_sign(&key, messages[i], sizeof(messages[i]),
                                  signatures[i], &sig_lens[i]);
        ASSERT_EQ(QTLS_SUCCESS, ret, "Multiple signatures should succeed");
    }

    /* 모든 서명 검증 */
    for (int i = 0; i < 3; i++) {
        ret = qtls_dilithium_verify(&key, messages[i], sizeof(messages[i]),
                                    signatures[i], sig_lens[i]);
        ASSERT_EQ(1, ret, "All signatures should verify");
    }

    /* 교차 검증 (서명1으로 메시지2 검증 - 실패해야 함) */
    ret = qtls_dilithium_verify(&key, messages[1], sizeof(messages[1]),
                                signatures[0], sig_lens[0]);
    ASSERT_EQ(0, ret, "Cross-verification should fail");

    qtls_secure_zero(&key, sizeof(key));
    for (int i = 0; i < 3; i++) {
        qtls_secure_zero(signatures[i], sizeof(signatures[i]));
    }

    TEST_PASS("test_dilithium_multiple_signatures");
    return 0;
}

/*
 * 메인 테스트 실행 함수
 */
int main(void) {
    printf("\n");
    printf("==========================================\n");
    printf("  Q-TLS DILITHIUM3 단위 테스트\n");
    printf("  ML-DSA-65 전자서명 알고리즘 검증\n");
    printf("==========================================\n\n");

    /* 모든 테스트 실행 */
    if (test_dilithium_keygen() != 0) tests_failed++;
    if (test_dilithium_sign() != 0) tests_failed++;
    if (test_dilithium_verify() != 0) tests_failed++;
    if (test_dilithium_invalid_signature() != 0) tests_failed++;
    if (test_dilithium_message_tampering() != 0) tests_failed++;
    if (test_dilithium_null_pointer() != 0) tests_failed++;
    if (test_dilithium_empty_message() != 0) tests_failed++;
    if (test_dilithium_multiple_signatures() != 0) tests_failed++;

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
