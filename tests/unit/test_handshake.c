/*
 * Q-TLS 핸드셰이크 단위 테스트
 * 하이브리드 TLS 핸드셰이크 프로토콜 테스트
 *
 * 테스트 항목:
 * - 하이브리드 마스터 시크릿 생성
 * - 세션 키 유도
 * - 키 유도 함수 (HKDF) 검증
 * - 랜덤 값 처리
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
 * 테스트 1: 하이브리드 마스터 시크릿 유도
 * ECDHE + KYBER 공유 비밀을 결합하여 마스터 시크릿 생성
 */
static int test_derive_master_secret(void) {
    TEST_START("test_derive_master_secret");

    QTLS_HYBRID_SECRET secret;
    int ret;

    /* 테스트용 공유 비밀 생성 (실제로는 ECDHE와 KYBER에서 얻음) */
    RAND_bytes(secret.classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    RAND_bytes(secret.pqc_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    RAND_bytes(secret.client_random, QTLS_MAX_RANDOM_LEN);
    RAND_bytes(secret.server_random, QTLS_MAX_RANDOM_LEN);

    /* 마스터 시크릿 유도 */
    ret = qtls_derive_master_secret(&secret);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Master secret derivation should succeed");

    /* 마스터 시크릿이 생성되었는지 확인 */
    int all_zeros = 1;
    for (int i = 0; i < QTLS_MAX_MASTER_SECRET; i++) {
        if (secret.master_secret[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Master secret should not be all zeros");

    qtls_secure_zero(&secret, sizeof(secret));

    TEST_PASS("test_derive_master_secret");
    return 0;
}

/*
 * 테스트 2: 세션 키 유도
 * 마스터 시크릿에서 AES 키와 IV 유도
 */
static int test_derive_session_keys(void) {
    TEST_START("test_derive_session_keys");

    QTLS_HYBRID_SECRET secret;
    QTLS_SESSION_KEYS keys;
    int ret;

    /* 테스트용 하이브리드 시크릿 준비 */
    RAND_bytes(secret.classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    RAND_bytes(secret.pqc_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    RAND_bytes(secret.client_random, QTLS_MAX_RANDOM_LEN);
    RAND_bytes(secret.server_random, QTLS_MAX_RANDOM_LEN);

    /* 마스터 시크릿 유도 */
    ret = qtls_derive_master_secret(&secret);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Master secret derivation should succeed");

    /* 세션 키 유도 */
    ret = qtls_derive_session_keys(&secret, &keys);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Session key derivation should succeed");

    /* 클라이언트 쓰기 키 확인 */
    int all_zeros = 1;
    for (int i = 0; i < 32; i++) {
        if (keys.client_write_key[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Client write key should not be all zeros");

    /* 서버 쓰기 키 확인 */
    all_zeros = 1;
    for (int i = 0; i < 32; i++) {
        if (keys.server_write_key[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    ASSERT_TRUE(!all_zeros, "Server write key should not be all zeros");

    /* 클라이언트와 서버 키가 다른지 확인 */
    ASSERT_TRUE(memcmp(keys.client_write_key, keys.server_write_key, 32) != 0,
                "Client and server keys should be different");

    qtls_secure_zero(&secret, sizeof(secret));
    qtls_secure_zero(&keys, sizeof(keys));

    TEST_PASS("test_derive_session_keys");
    return 0;
}

/*
 * 테스트 3: 결정적 키 유도
 * 같은 입력에서 항상 같은 출력이 나오는지 확인
 */
static int test_deterministic_key_derivation(void) {
    TEST_START("test_deterministic_key_derivation");

    QTLS_HYBRID_SECRET secret1, secret2;
    int ret;

    /* 같은 입력 준비 */
    memset(&secret1, 0, sizeof(secret1));
    memset(&secret2, 0, sizeof(secret2));

    /* 동일한 테스트 벡터 사용 */
    memset(secret1.classical_secret, 0xAA, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memset(secret1.pqc_secret, 0xBB, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    memset(secret1.client_random, 0xCC, QTLS_MAX_RANDOM_LEN);
    memset(secret1.server_random, 0xDD, QTLS_MAX_RANDOM_LEN);

    memcpy(&secret2, &secret1, sizeof(secret1));

    /* 두 번 유도 */
    ret = qtls_derive_master_secret(&secret1);
    ASSERT_EQ(QTLS_SUCCESS, ret, "First derivation should succeed");

    ret = qtls_derive_master_secret(&secret2);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Second derivation should succeed");

    /* 결과가 동일한지 확인 (결정적 동작) */
    ASSERT_TRUE(memcmp(secret1.master_secret, secret2.master_secret,
                       QTLS_MAX_MASTER_SECRET) == 0,
                "Same input should produce same master secret");

    qtls_secure_zero(&secret1, sizeof(secret1));
    qtls_secure_zero(&secret2, sizeof(secret2));

    TEST_PASS("test_deterministic_key_derivation");
    return 0;
}

/*
 * 테스트 4: 다른 입력에서 다른 출력
 * 입력이 조금만 달라도 완전히 다른 키가 생성되는지 확인
 */
static int test_different_inputs_different_outputs(void) {
    TEST_START("test_different_inputs_different_outputs");

    QTLS_HYBRID_SECRET secret1, secret2;
    int ret;

    /* 거의 동일한 입력 준비 */
    memset(&secret1, 0, sizeof(secret1));
    memset(&secret2, 0, sizeof(secret2));

    memset(secret1.classical_secret, 0xAA, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memset(secret1.pqc_secret, 0xBB, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    memset(secret1.client_random, 0xCC, QTLS_MAX_RANDOM_LEN);
    memset(secret1.server_random, 0xDD, QTLS_MAX_RANDOM_LEN);

    memcpy(&secret2, &secret1, sizeof(secret1));

    /* secret2의 클라이언트 랜덤 1바이트만 변경 */
    secret2.client_random[0] ^= 0x01;

    /* 키 유도 */
    ret = qtls_derive_master_secret(&secret1);
    ASSERT_EQ(QTLS_SUCCESS, ret, "First derivation should succeed");

    ret = qtls_derive_master_secret(&secret2);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Second derivation should succeed");

    /* 결과가 달라야 함 (눈사태 효과) */
    ASSERT_TRUE(memcmp(secret1.master_secret, secret2.master_secret,
                       QTLS_MAX_MASTER_SECRET) != 0,
                "Different input should produce different master secret");

    qtls_secure_zero(&secret1, sizeof(secret1));
    qtls_secure_zero(&secret2, sizeof(secret2));

    TEST_PASS("test_different_inputs_different_outputs");
    return 0;
}

/*
 * 테스트 5: NULL 포인터 에러 처리
 */
static int test_handshake_null_pointer(void) {
    TEST_START("test_handshake_null_pointer");

    QTLS_HYBRID_SECRET secret;
    QTLS_SESSION_KEYS keys;
    int ret;

    /* 테스트용 시크릿 준비 */
    RAND_bytes(secret.classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    RAND_bytes(secret.pqc_secret, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    RAND_bytes(secret.client_random, QTLS_MAX_RANDOM_LEN);
    RAND_bytes(secret.server_random, QTLS_MAX_RANDOM_LEN);
    ret = qtls_derive_master_secret(&secret);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Setup should succeed");

    /* NULL 포인터 테스트 */
    ret = qtls_derive_master_secret(NULL);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret,
              "NULL secret should return error");

    ret = qtls_derive_session_keys(NULL, &keys);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret,
              "NULL secret should return error");

    ret = qtls_derive_session_keys(&secret, NULL);
    ASSERT_EQ(QTLS_ERROR_NULL_POINTER, ret,
              "NULL keys should return error");

    qtls_secure_zero(&secret, sizeof(secret));

    TEST_PASS("test_handshake_null_pointer");
    return 0;
}

/*
 * 테스트 6: 완전한 핸드셰이크 시뮬레이션
 * KYBER KEM과 키 유도를 통합 테스트
 */
static int test_full_handshake_simulation(void) {
    TEST_START("test_full_handshake_simulation");

    QTLS_KYBER_KEY server_kyber, client_kyber;
    QTLS_HYBRID_SECRET client_secret, server_secret;
    QTLS_SESSION_KEYS client_keys, server_keys;
    int ret;

    /* 1. 서버: KYBER 키 생성 */
    ret = qtls_kyber_keygen(&server_kyber);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Server KYBER keygen should succeed");

    /* 2. 클라이언트: 서버 공개키로 캡슐화 */
    memcpy(client_kyber.public_key, server_kyber.public_key,
           QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    client_kyber.has_secret_key = 0;

    ret = qtls_kyber_encapsulate(&client_kyber);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Client KYBER encapsulation should succeed");

    /* 3. 서버: 암호문 역캡슐화 */
    memcpy(server_kyber.ciphertext, client_kyber.ciphertext,
           QTLS_KYBER1024_CIPHERTEXT_BYTES);

    ret = qtls_kyber_decapsulate(&server_kyber);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Server KYBER decapsulation should succeed");

    /* 4. 양쪽 공유 비밀 확인 */
    ASSERT_TRUE(memcmp(client_kyber.shared_secret, server_kyber.shared_secret,
                       QTLS_KYBER1024_SHARED_SECRET_BYTES) == 0,
                "KYBER shared secrets must match");

    /* 5. 하이브리드 시크릿 준비 (ECDHE 시뮬레이션) */
    RAND_bytes(client_secret.classical_secret, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memcpy(client_secret.pqc_secret, client_kyber.shared_secret,
           QTLS_KYBER1024_SHARED_SECRET_BYTES);
    RAND_bytes(client_secret.client_random, QTLS_MAX_RANDOM_LEN);
    RAND_bytes(client_secret.server_random, QTLS_MAX_RANDOM_LEN);

    /* 서버도 동일한 시크릿 사용 */
    memcpy(&server_secret, &client_secret, sizeof(client_secret));
    memcpy(server_secret.pqc_secret, server_kyber.shared_secret,
           QTLS_KYBER1024_SHARED_SECRET_BYTES);

    /* 6. 마스터 시크릿 유도 */
    ret = qtls_derive_master_secret(&client_secret);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Client master secret should succeed");

    ret = qtls_derive_master_secret(&server_secret);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Server master secret should succeed");

    /* 7. 양쪽 마스터 시크릿이 동일한지 확인 */
    ASSERT_TRUE(memcmp(client_secret.master_secret, server_secret.master_secret,
                       QTLS_MAX_MASTER_SECRET) == 0,
                "Master secrets must match");

    /* 8. 세션 키 유도 */
    ret = qtls_derive_session_keys(&client_secret, &client_keys);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Client session keys should succeed");

    ret = qtls_derive_session_keys(&server_secret, &server_keys);
    ASSERT_EQ(QTLS_SUCCESS, ret, "Server session keys should succeed");

    /* 9. 양쪽 세션 키가 동일한지 확인 */
    ASSERT_TRUE(memcmp(&client_keys, &server_keys, sizeof(client_keys)) == 0,
                "Session keys must match");

    /* 정리 */
    qtls_secure_zero(&server_kyber, sizeof(server_kyber));
    qtls_secure_zero(&client_kyber, sizeof(client_kyber));
    qtls_secure_zero(&client_secret, sizeof(client_secret));
    qtls_secure_zero(&server_secret, sizeof(server_secret));
    qtls_secure_zero(&client_keys, sizeof(client_keys));
    qtls_secure_zero(&server_keys, sizeof(server_keys));

    TEST_PASS("test_full_handshake_simulation");
    return 0;
}

/*
 * 메인 테스트 실행 함수
 */
int main(void) {
    printf("\n");
    printf("==========================================\n");
    printf("  Q-TLS 핸드셰이크 단위 테스트\n");
    printf("  하이브리드 키 유도 프로토콜 검증\n");
    printf("==========================================\n\n");

    /* 모든 테스트 실행 */
    if (test_derive_master_secret() != 0) tests_failed++;
    if (test_derive_session_keys() != 0) tests_failed++;
    if (test_deterministic_key_derivation() != 0) tests_failed++;
    if (test_different_inputs_different_outputs() != 0) tests_failed++;
    if (test_handshake_null_pointer() != 0) tests_failed++;
    if (test_full_handshake_simulation() != 0) tests_failed++;

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
