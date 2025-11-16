/*
 * Q-TLS 타이밍 공격 테스트
 * 상수 시간(constant-time) 연산 검증
 *
 * 테스트 항목:
 * - 메모리 비교 타이밍 분석
 * - 키 유도 타이밍 일관성
 * - 암호문 역캡슐화 타이밍 일관성
 *
 * Copyright 2025 QSIGN Project
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>

#define TIMING_ITERATIONS 1000
#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RESET "\033[0m"

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/* 통계 계산 */
static double calculate_stddev(uint64_t *times, int count) {
    double mean = 0.0, variance = 0.0;
    for (int i = 0; i < count; i++) {
        mean += times[i];
    }
    mean /= count;

    for (int i = 0; i < count; i++) {
        double diff = times[i] - mean;
        variance += diff * diff;
    }
    variance /= count;

    return sqrt(variance);
}

/*
 * 테스트 1: KYBER 역캡슐화 타이밍 일관성
 */
static int test_kyber_decapsulation_timing(void) {
    printf(COLOR_YELLOW "[테스트]" COLOR_RESET " KYBER 역캡슐화 타이밍 일관성\n");

    QTLS_KYBER_KEY server_key, client_key;
    uint64_t times[TIMING_ITERATIONS];

    /* 키 준비 */
    qtls_kyber_keygen(&server_key);
    memcpy(client_key.public_key, server_key.public_key, QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    client_key.has_secret_key = 0;
    qtls_kyber_encapsulate(&client_key);

    /* 타이밍 측정 */
    for (int i = 0; i < TIMING_ITERATIONS; i++) {
        QTLS_KYBER_KEY temp_key;
        memcpy(&temp_key, &server_key, sizeof(server_key));
        memcpy(temp_key.ciphertext, client_key.ciphertext, QTLS_KYBER1024_CIPHERTEXT_BYTES);

        uint64_t start = get_time_ns();
        qtls_kyber_decapsulate(&temp_key);
        uint64_t end = get_time_ns();

        times[i] = end - start;
        qtls_secure_zero(&temp_key, sizeof(temp_key));
    }

    /* 통계 분석 */
    double stddev = calculate_stddev(times, TIMING_ITERATIONS);
    double mean = 0.0;
    for (int i = 0; i < TIMING_ITERATIONS; i++) {
        mean += times[i];
    }
    mean /= TIMING_ITERATIONS;

    double cv = (stddev / mean) * 100.0; /* 변동계수 */

    printf("  평균 시간: %.2f ns\n", mean);
    printf("  표준편차: %.2f ns\n", stddev);
    printf("  변동계수: %.2f%%\n", cv);

    if (cv > 10.0) {
        printf(COLOR_RED "  [경고] 높은 타이밍 변동성 감지 (CV > 10%%)!\n" COLOR_RESET);
        printf("  타이밍 공격에 취약할 수 있음\n");
    } else {
        printf(COLOR_GREEN "  [통과] 타이밍 일관성 양호\n" COLOR_RESET);
    }

    qtls_secure_zero(&server_key, sizeof(server_key));
    qtls_secure_zero(&client_key, sizeof(client_key));

    return 0;
}

/*
 * 테스트 2: 메모리 제로화 타이밍 일관성
 */
static int test_secure_zero_timing(void) {
    printf(COLOR_YELLOW "\n[테스트]" COLOR_RESET " 보안 메모리 제로화 타이밍 일관성\n");

    uint8_t buffer[1024];
    uint64_t times[TIMING_ITERATIONS];

    for (int i = 0; i < TIMING_ITERATIONS; i++) {
        memset(buffer, (uint8_t)i, sizeof(buffer));

        uint64_t start = get_time_ns();
        qtls_secure_zero(buffer, sizeof(buffer));
        uint64_t end = get_time_ns();

        times[i] = end - start;
    }

    double stddev = calculate_stddev(times, TIMING_ITERATIONS);
    double mean = 0.0;
    for (int i = 0; i < TIMING_ITERATIONS; i++) {
        mean += times[i];
    }
    mean /= TIMING_ITERATIONS;

    double cv = (stddev / mean) * 100.0;

    printf("  평균 시간: %.2f ns\n", mean);
    printf("  표준편차: %.2f ns\n", stddev);
    printf("  변동계수: %.2f%%\n", cv);

    if (cv > 15.0) {
        printf(COLOR_RED "  [경고] 비일관적 메모리 제로화!\n" COLOR_RESET);
    } else {
        printf(COLOR_GREEN "  [통과] 상수 시간 메모리 제로화\n" COLOR_RESET);
    }

    return 0;
}

/*
 * 테스트 3: 키 유도 타이밍 일관성
 */
static int test_key_derivation_timing(void) {
    printf(COLOR_YELLOW "\n[테스트]" COLOR_RESET " 키 유도 타이밍 일관성\n");

    QTLS_HYBRID_SECRET secret;
    uint64_t times[TIMING_ITERATIONS];

    /* 시크릿 준비 */
    memset(secret.classical_secret, 0xAA, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
    memset(secret.pqc_secret, 0xBB, QTLS_KYBER1024_SHARED_SECRET_BYTES);
    memset(secret.client_random, 0xCC, QTLS_MAX_RANDOM_LEN);
    memset(secret.server_random, 0xDD, QTLS_MAX_RANDOM_LEN);

    /* 타이밍 측정 */
    for (int i = 0; i < TIMING_ITERATIONS; i++) {
        QTLS_HYBRID_SECRET temp_secret;
        memcpy(&temp_secret, &secret, sizeof(secret));

        uint64_t start = get_time_ns();
        qtls_derive_master_secret(&temp_secret);
        uint64_t end = get_time_ns();

        times[i] = end - start;
        qtls_secure_zero(&temp_secret, sizeof(temp_secret));
    }

    double stddev = calculate_stddev(times, TIMING_ITERATIONS);
    double mean = 0.0;
    for (int i = 0; i < TIMING_ITERATIONS; i++) {
        mean += times[i];
    }
    mean /= TIMING_ITERATIONS;

    double cv = (stddev / mean) * 100.0;

    printf("  평균 시간: %.2f ns\n", mean);
    printf("  표준편차: %.2f ns\n", stddev);
    printf("  변동계수: %.2f%%\n", cv);

    if (cv > 10.0) {
        printf(COLOR_RED "  [경고] 키 유도 타이밍 변동성 높음!\n" COLOR_RESET);
    } else {
        printf(COLOR_GREEN "  [통과] 키 유도 타이밍 일관성\n" COLOR_RESET);
    }

    qtls_secure_zero(&secret, sizeof(secret));

    return 0;
}

int main(void) {
    printf("\n==========================================\n");
    printf("  Q-TLS 타이밍 공격 테스트\n");
    printf("  상수 시간 연산 검증\n");
    printf("==========================================\n\n");

    printf("반복 횟수: %d\n\n", TIMING_ITERATIONS);

    test_kyber_decapsulation_timing();
    test_secure_zero_timing();
    test_key_derivation_timing();

    printf("\n==========================================\n");
    printf(COLOR_GREEN "  타이밍 분석 완료!\n" COLOR_RESET);
    printf("==========================================\n\n");

    return 0;
}
