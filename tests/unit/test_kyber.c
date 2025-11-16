/*
 * Q-TLS KYBER1024 단위 테스트
 * KYBER1024 (ML-KEM-1024) 암호화 알고리즘 테스트
 *
 * 테스트 항목:
 * - 키 생성 (keygen)
 * - 캡슐화 (encapsulation)
 * - 역캡슐화 (decapsulation)
 * - 공유 비밀 일치 확인
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
 * 테스트 1: KYBER1024 키 생성
 * 공개키와 비밀키가 올바르게 생성되는지 확인
 */
static int test_kyber_keygen(void) {
    TEST_START("test_kyber_keygen");

    QTLS_KYBER_KEY key;
    int ret;

    /* 키 생성 실행 */
    ret = qtls_kyber_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "qtls_kyber_keygen should succeed");

    /* 비밀키 플래그 확인 */
    ASSERT_TRUE(key.has_secret_key == 1, "Should have secret key");
    ASSERT_TRUE(key.has_shared_secret == 0, "Should not have shared secret yet");

    /* 키 데이터가 0이 아닌지 확인 (실제로 생성되었는지) */
    int all_zeros = 1;
    for (int i = 0; i < QTLS_KYBER1024_PUBLIC_KEY_BYTES; i++) {
        if (key.public_key[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Public key should not be all zeros");

    /* 키 정리 (보안상 중요) */
    qtls_secure_zero(&key, sizeof(key));

    TEST_PASS("test_kyber_keygen");
    return 0;
}

/*
 * 테스트 2: KYBER1024 캡슐화
 * 공개키로 공유 비밀을 캡슐화하는지 확인
 */
static int test_kyber_encapsulate(void) {
    TEST_START("test_kyber_encapsulate");

    QTLS_KYBER_KEY key;
    int ret;

    /* 먼저 키 생성 */
    ret = qtls_kyber_keygen(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Key generation should succeed");

    /* 캡슐화 실행 (클라이언트 측 동작) */
    ret = qtls_kyber_encapsulate(&key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "qtls_kyber_encapsulate should succeed");

    /* 공유 비밀 플래그 확인 */
    ASSERT_TRUE(key.has_shared_secret == 1, "Should have shared secret after encapsulation");

    /* 암호문이 생성되었는지 확인 */
    int all_zeros = 1;
    for (int i = 0; i < QTLS_KYBER1024_CIPHERTEXT_BYTES; i++) {
        if (key.ciphertext[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Ciphertext should not be all zeros");

    /* 공유 비밀이 생성되었는지 확인 */
    all_zeros = 1;
    for (int i = 0; i < QTLS_KYBER1024_SHARED_SECRET_BYTES; i++) {
        if (key.shared_secret[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Shared secret should not be all zeros");

    qtls_secure_zero(&key, sizeof(key));

    TEST_PASS("test_kyber_encapsulate");
    return 0;
}

/*
 * 테스트 3: KYBER1024 역캡슐화
 * 비밀키로 암호문을 해독하여 공유 비밀을 얻는지 확인
 */
static int test_kyber_decapsulate(void) {
    TEST_START("test_kyber_decapsulate");

    QTLS_KYBER_KEY server_key, client_key;
    int ret;

    /* 서버: 키 생성 */
    ret = qtls_kyber_keygen(&server_key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Server key generation should succeed");

    /* 클라이언트: 서버의 공개키를 복사 */
    memcpy(client_key.public_key, server_key.public_key,
           QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    client_key.has_secret_key = 0;
    client_key.has_shared_secret = 0;

    /* 클라이언트: 캡슐화 (공유 비밀 생성) */
    ret = qtls_kyber_encapsulate(&client_key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Client encapsulation should succeed");

    /* 서버: 클라이언트의 암호문을 복사 */
    memcpy(server_key.ciphertext, client_key.ciphertext,
           QTLS_KYBER1024_CIPHERTEXT_BYTES);

    /* 서버: 역캡슐화 (공유 비밀 복원) */
    ret = qtls_kyber_decapsulate(&server_key);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Server decapsulation should succeed");

    /* 양쪽의 공유 비밀이 일치하는지 확인 (핵심 테스트!) */
    ASSERT_TRUE(memcmp(client_key.shared_secret, server_key.shared_secret,
                       QTLS_KYBER1024_SHARED_SECRET_BYTES) == 0,
                "Client and server shared secrets must match");

    qtls_secure_zero(&server_key, sizeof(server_key));
    qtls_secure_zero(&client_key, sizeof(client_key));

    TEST_PASS("test_kyber_decapsulate");
    return 0;
}

/*
 * 테스트 4: NULL 포인터 에러 처리
 * NULL 입력에 대해 적절한 에러를 반환하는지 확인
 */
static int test_kyber_null_pointer(void) {
    TEST_START("test_kyber_null_pointer");

    int ret;

    /* NULL 포인터로 키 생성 시도 */
    ret = qtls_kyber_keygen(NULL);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret,
              "qtls_kyber_keygen(NULL) should return NULL_POINTER error");

    /* NULL 포인터로 캡슐화 시도 */
    ret = qtls_kyber_encapsulate(NULL);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret,
              "qtls_kyber_encapsulate(NULL) should return NULL_POINTER error");

    /* NULL 포인터로 역캡슐화 시도 */
    ret = qtls_kyber_decapsulate(NULL);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret,
              "qtls_kyber_decapsulate(NULL) should return NULL_POINTER error");

    TEST_PASS("test_kyber_null_pointer");
    return 0;
}

/*
 * 테스트 5: 비밀키 없이 역캡슐화 시도
 * 비밀키가 없는 상태에서 역캡슐화 시 에러 확인
 */
static int test_kyber_decapsulate_without_secret_key(void) {
    TEST_START("test_kyber_decapsulate_without_secret_key");

    QTLS_KYBER_KEY key;
    int ret;

    /* 키 구조체 초기화 (비밀키 없음) */
    memset(&key, 0, sizeof(key));
    key.has_secret_key = 0;

    /* 비밀키 없이 역캡슐화 시도 */
    ret = qtls_kyber_decapsulate(&key);
    ASSERT_EQ(QTLS_ERROR_INVALID_ARGUMENT, ret,
              "Decapsulation without secret key should fail");

    TEST_PASS("test_kyber_decapsulate_without_secret_key");
    return 0;
}

/*
 * 테스트 6: 여러 번 키 생성 (안정성 테스트)
 * 연속으로 키를 생성해도 문제없는지 확인
 */
static int test_kyber_multiple_keygen(void) {
    TEST_START("test_kyber_multiple_keygen");

    QTLS_KYBER_KEY keys[5];
    int ret;

    /* 5개의 키 쌍 생성 */
    for (int i = 0; i < 5; i++) {
        ret = qtls_kyber_keygen(&keys[i]);
        ASSERT_EQ(QTLS_SUCCESS, ret, "Multiple key generation should succeed");
        ASSERT_TRUE(keys[i].has_secret_key == 1, "Each key should have secret key");
    }

    /* 생성된 키들이 서로 다른지 확인 */
    for (int i = 0; i < 4; i++) {
        ASSERT_TRUE(memcmp(keys[i].public_key, keys[i+1].public_key,
                           QTLS_KYBER1024_PUBLIC_KEY_BYTES) != 0,
                    "Generated keys should be different");
    }

    /* 모든 키 정리 */
    for (int i = 0; i < 5; i++) {
        qtls_secure_zero(&keys[i], sizeof(QTLS_KYBER_KEY));
    }

    TEST_PASS("test_kyber_multiple_keygen");
    return 0;
}

/*
 * 메인 테스트 실행 함수
 */
int main(void) {
    printf("\n");
    printf("==========================================\n");
    printf("  Q-TLS KYBER1024 단위 테스트\n");
    printf("  ML-KEM-1024 암호화 알고리즘 검증\n");
    printf("==========================================\n\n");

    /* 모든 테스트 실행 */
    if (test_kyber_keygen() != 0) tests_failed++;
    if (test_kyber_encapsulate() != 0) tests_failed++;
    if (test_kyber_decapsulate() != 0) tests_failed++;
    if (test_kyber_null_pointer() != 0) tests_failed++;
    if (test_kyber_decapsulate_without_secret_key() != 0) tests_failed++;
    if (test_kyber_multiple_keygen() != 0) tests_failed++;

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
