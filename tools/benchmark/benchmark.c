/*
 * Q-TLS 성능 벤치마크 도구
 * KYBER1024, DILITHIUM3, 핸드셰이크 성능 측정
 *
 * 측정 항목:
 * - KYBER1024: keygen, encapsulate, decapsulate (ops/sec)
 * - DILITHIUM3: keygen, sign, verify (ops/sec)
 * - 핸드셰이크: 전체 시간, 처리량
 * - 메모리 사용량
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

/* 색상 출력 */
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_CYAN    "\033[0;36m"
#define COLOR_RESET   "\033[0m"

/* 벤치마크 설정 */
#define WARMUP_ITERATIONS 10
#define BENCHMARK_ITERATIONS 100
#define MESSAGE_SIZE 1024

/*
 * 현재 시간을 마이크로초 단위로 반환
 */
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/*
 * 메모리 사용량 가져오기 (KB)
 */
static long get_memory_usage_kb(void) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

/*
 * 벤치마크 결과 출력
 */
static void print_benchmark_result(const char *name, uint64_t total_time_us,
                                     int iterations, size_t data_size) {
    double avg_time_us = (double)total_time_us / iterations;
    double avg_time_ms = avg_time_us / 1000.0;
    double ops_per_sec = 1000000.0 / avg_time_us;

    printf("  %-30s ", name);
    printf("평균: %8.2f ms  ", avg_time_ms);
    printf("처리량: %8.0f ops/sec", ops_per_sec);

    if (data_size > 0) {
        double throughput_mbps = (data_size * ops_per_sec * 8.0) / (1024.0 * 1024.0);
        printf("  %6.2f Mbps", throughput_mbps);
    }

    printf("\n");
}

/*
 * 벤치마크 1: KYBER1024 키 생성
 */
static void benchmark_kyber_keygen(void) {
    QTLS_KYBER_KEY key;
    uint64_t start, end, total_time = 0;
    int i;

    printf(COLOR_CYAN "KYBER1024 키 생성 벤치마크\n" COLOR_RESET);

    /* 워밍업 */
    for (i = 0; i < WARMUP_ITERATIONS; i++) {
        qtls_kyber_keygen(&key);
        qtls_secure_zero(&key, sizeof(key));
    }

    /* 실제 측정 */
    for (i = 0; i < BENCHMARK_ITERATIONS; i++) {
        start = get_time_us();
        qtls_kyber_keygen(&key);
        end = get_time_us();

        total_time += (end - start);
        qtls_secure_zero(&key, sizeof(key));
    }

    print_benchmark_result("KYBER1024 keygen", total_time, BENCHMARK_ITERATIONS, 0);
}

/*
 * 벤치마크 2: KYBER1024 캡슐화
 */
static void benchmark_kyber_encapsulate(void) {
    QTLS_KYBER_KEY key;
    uint64_t start, end, total_time = 0;
    int i;

    printf(COLOR_CYAN "KYBER1024 캡슐화 벤치마크\n" COLOR_RESET);

    /* 키 준비 */
    qtls_kyber_keygen(&key);

    /* 워밍업 */
    for (i = 0; i < WARMUP_ITERATIONS; i++) {
        QTLS_KYBER_KEY temp_key;
        memcpy(temp_key.public_key, key.public_key, QTLS_KYBER1024_PUBLIC_KEY_BYTES);
        temp_key.has_secret_key = 0;
        qtls_kyber_encapsulate(&temp_key);
        qtls_secure_zero(&temp_key, sizeof(temp_key));
    }

    /* 실제 측정 */
    for (i = 0; i < BENCHMARK_ITERATIONS; i++) {
        QTLS_KYBER_KEY temp_key;
        memcpy(temp_key.public_key, key.public_key, QTLS_KYBER1024_PUBLIC_KEY_BYTES);
        temp_key.has_secret_key = 0;

        start = get_time_us();
        qtls_kyber_encapsulate(&temp_key);
        end = get_time_us();

        total_time += (end - start);
        qtls_secure_zero(&temp_key, sizeof(temp_key));
    }

    qtls_secure_zero(&key, sizeof(key));
    print_benchmark_result("KYBER1024 encapsulate", total_time, BENCHMARK_ITERATIONS, 0);
}

/*
 * 벤치마크 3: KYBER1024 역캡슐화
 */
static void benchmark_kyber_decapsulate(void) {
    QTLS_KYBER_KEY server_key, client_key;
    uint64_t start, end, total_time = 0;
    int i;

    printf(COLOR_CYAN "KYBER1024 역캡슐화 벤치마크\n" COLOR_RESET);

    /* 키 및 암호문 준비 */
    qtls_kyber_keygen(&server_key);
    memcpy(client_key.public_key, server_key.public_key, QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    client_key.has_secret_key = 0;
    qtls_kyber_encapsulate(&client_key);

    /* 워밍업 */
    for (i = 0; i < WARMUP_ITERATIONS; i++) {
        QTLS_KYBER_KEY temp_key;
        memcpy(&temp_key, &server_key, sizeof(server_key));
        memcpy(temp_key.ciphertext, client_key.ciphertext, QTLS_KYBER1024_CIPHERTEXT_BYTES);
        qtls_kyber_decapsulate(&temp_key);
        qtls_secure_zero(&temp_key, sizeof(temp_key));
    }

    /* 실제 측정 */
    for (i = 0; i < BENCHMARK_ITERATIONS; i++) {
        QTLS_KYBER_KEY temp_key;
        memcpy(&temp_key, &server_key, sizeof(server_key));
        memcpy(temp_key.ciphertext, client_key.ciphertext, QTLS_KYBER1024_CIPHERTEXT_BYTES);

        start = get_time_us();
        qtls_kyber_decapsulate(&temp_key);
        end = get_time_us();

        total_time += (end - start);
        qtls_secure_zero(&temp_key, sizeof(temp_key));
    }

    qtls_secure_zero(&server_key, sizeof(server_key));
    qtls_secure_zero(&client_key, sizeof(client_key));
    print_benchmark_result("KYBER1024 decapsulate", total_time, BENCHMARK_ITERATIONS, 0);
}

/*
 * 벤치마크 4: DILITHIUM3 키 생성
 */
static void benchmark_dilithium_keygen(void) {
    QTLS_DILITHIUM_KEY key;
    uint64_t start, end, total_time = 0;
    int i;

    printf(COLOR_CYAN "\nDILITHIUM3 키 생성 벤치마크\n" COLOR_RESET);

    /* 워밍업 */
    for (i = 0; i < WARMUP_ITERATIONS; i++) {
        qtls_dilithium_keygen(&key);
        qtls_secure_zero(&key, sizeof(key));
    }

    /* 실제 측정 */
    for (i = 0; i < BENCHMARK_ITERATIONS; i++) {
        start = get_time_us();
        qtls_dilithium_keygen(&key);
        end = get_time_us();

        total_time += (end - start);
        qtls_secure_zero(&key, sizeof(key));
    }

    print_benchmark_result("DILITHIUM3 keygen", total_time, BENCHMARK_ITERATIONS, 0);
}

/*
 * 벤치마크 5: DILITHIUM3 서명
 */
static void benchmark_dilithium_sign(void) {
    QTLS_DILITHIUM_KEY key;
    uint8_t message[MESSAGE_SIZE];
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;
    uint64_t start, end, total_time = 0;
    int i;

    printf(COLOR_CYAN "DILITHIUM3 서명 벤치마크 (메시지 크기: %d bytes)\n" COLOR_RESET,
           MESSAGE_SIZE);

    /* 키 및 메시지 준비 */
    qtls_dilithium_keygen(&key);
    memset(message, 0xAA, sizeof(message));

    /* 워밍업 */
    for (i = 0; i < WARMUP_ITERATIONS; i++) {
        qtls_dilithium_sign(&key, message, sizeof(message), signature, &sig_len);
    }

    /* 실제 측정 */
    for (i = 0; i < BENCHMARK_ITERATIONS; i++) {
        start = get_time_us();
        qtls_dilithium_sign(&key, message, sizeof(message), signature, &sig_len);
        end = get_time_us();

        total_time += (end - start);
    }

    qtls_secure_zero(&key, sizeof(key));
    qtls_secure_zero(signature, sizeof(signature));
    print_benchmark_result("DILITHIUM3 sign", total_time, BENCHMARK_ITERATIONS, MESSAGE_SIZE);
}

/*
 * 벤치마크 6: DILITHIUM3 검증
 */
static void benchmark_dilithium_verify(void) {
    QTLS_DILITHIUM_KEY key;
    uint8_t message[MESSAGE_SIZE];
    uint8_t signature[QTLS_DILITHIUM3_SIGNATURE_BYTES];
    size_t sig_len;
    uint64_t start, end, total_time = 0;
    int i;

    printf(COLOR_CYAN "DILITHIUM3 검증 벤치마크\n" COLOR_RESET);

    /* 키, 메시지, 서명 준비 */
    qtls_dilithium_keygen(&key);
    memset(message, 0xAA, sizeof(message));
    qtls_dilithium_sign(&key, message, sizeof(message), signature, &sig_len);

    /* 워밍업 */
    for (i = 0; i < WARMUP_ITERATIONS; i++) {
        qtls_dilithium_verify(&key, message, sizeof(message), signature, sig_len);
    }

    /* 실제 측정 */
    for (i = 0; i < BENCHMARK_ITERATIONS; i++) {
        start = get_time_us();
        qtls_dilithium_verify(&key, message, sizeof(message), signature, sig_len);
        end = get_time_us();

        total_time += (end - start);
    }

    qtls_secure_zero(&key, sizeof(key));
    qtls_secure_zero(signature, sizeof(signature));
    print_benchmark_result("DILITHIUM3 verify", total_time, BENCHMARK_ITERATIONS, MESSAGE_SIZE);
}

/*
 * 벤치마크 7: 전체 핸드셰이크
 */
static void benchmark_full_handshake(void) {
    uint64_t start, end, total_time = 0;
    int i;

    printf(COLOR_CYAN "\n전체 핸드셰이크 벤치마크\n" COLOR_RESET);

    /* 워밍업 */
    for (i = 0; i < WARMUP_ITERATIONS / 2; i++) {
        QTLS_KYBER_KEY server_kyber, client_kyber;
        QTLS_HYBRID_SECRET secret;
        QTLS_SESSION_KEYS keys;

        qtls_kyber_keygen(&server_kyber);
        memcpy(client_kyber.public_key, server_kyber.public_key,
               QTLS_KYBER1024_PUBLIC_KEY_BYTES);
        client_kyber.has_secret_key = 0;
        qtls_kyber_encapsulate(&client_kyber);
        memcpy(server_kyber.ciphertext, client_kyber.ciphertext,
               QTLS_KYBER1024_CIPHERTEXT_BYTES);
        qtls_kyber_decapsulate(&server_kyber);

        memset(secret.classical_secret, 0xAA, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
        memcpy(secret.pqc_secret, server_kyber.shared_secret,
               QTLS_KYBER1024_SHARED_SECRET_BYTES);
        memset(secret.client_random, 0xCC, QTLS_MAX_RANDOM_LEN);
        memset(secret.server_random, 0xDD, QTLS_MAX_RANDOM_LEN);
        qtls_derive_master_secret(&secret);
        qtls_derive_session_keys(&secret, &keys);

        qtls_secure_zero(&server_kyber, sizeof(server_kyber));
        qtls_secure_zero(&client_kyber, sizeof(client_kyber));
        qtls_secure_zero(&secret, sizeof(secret));
        qtls_secure_zero(&keys, sizeof(keys));
    }

    /* 실제 측정 */
    for (i = 0; i < BENCHMARK_ITERATIONS / 2; i++) {
        QTLS_KYBER_KEY server_kyber, client_kyber;
        QTLS_HYBRID_SECRET secret;
        QTLS_SESSION_KEYS keys;

        start = get_time_us();

        /* 1. KYBER 키 교환 */
        qtls_kyber_keygen(&server_kyber);
        memcpy(client_kyber.public_key, server_kyber.public_key,
               QTLS_KYBER1024_PUBLIC_KEY_BYTES);
        client_kyber.has_secret_key = 0;
        qtls_kyber_encapsulate(&client_kyber);
        memcpy(server_kyber.ciphertext, client_kyber.ciphertext,
               QTLS_KYBER1024_CIPHERTEXT_BYTES);
        qtls_kyber_decapsulate(&server_kyber);

        /* 2. 하이브리드 시크릿 유도 */
        memset(secret.classical_secret, 0xAA, QTLS_ECDHE_P384_SHARED_SECRET_BYTES);
        memcpy(secret.pqc_secret, server_kyber.shared_secret,
               QTLS_KYBER1024_SHARED_SECRET_BYTES);
        memset(secret.client_random, 0xCC, QTLS_MAX_RANDOM_LEN);
        memset(secret.server_random, 0xDD, QTLS_MAX_RANDOM_LEN);
        qtls_derive_master_secret(&secret);

        /* 3. 세션 키 유도 */
        qtls_derive_session_keys(&secret, &keys);

        end = get_time_us();
        total_time += (end - start);

        qtls_secure_zero(&server_kyber, sizeof(server_kyber));
        qtls_secure_zero(&client_kyber, sizeof(client_kyber));
        qtls_secure_zero(&secret, sizeof(secret));
        qtls_secure_zero(&keys, sizeof(keys));
    }

    print_benchmark_result("전체 핸드셰이크", total_time, BENCHMARK_ITERATIONS / 2, 0);
}

/*
 * 메인 함수
 */
int main(void) {
    long mem_before, mem_after;

    printf("\n");
    printf("=========================================================\n");
    printf("  Q-TLS 성능 벤치마크\n");
    printf("  양자내성 암호화 알고리즘 성능 측정\n");
    printf("=========================================================\n\n");

    printf(COLOR_YELLOW "설정:\n" COLOR_RESET);
    printf("  워밍업 반복 횟수: %d\n", WARMUP_ITERATIONS);
    printf("  벤치마크 반복 횟수: %d\n", BENCHMARK_ITERATIONS);
    printf("  메시지 크기: %d bytes\n", MESSAGE_SIZE);
    printf("\n");

    mem_before = get_memory_usage_kb();

    /* 벤치마크 실행 */
    benchmark_kyber_keygen();
    benchmark_kyber_encapsulate();
    benchmark_kyber_decapsulate();

    benchmark_dilithium_keygen();
    benchmark_dilithium_sign();
    benchmark_dilithium_verify();

    benchmark_full_handshake();

    mem_after = get_memory_usage_kb();

    /* 메모리 사용량 */
    printf("\n");
    printf(COLOR_YELLOW "메모리 사용량:\n" COLOR_RESET);
    printf("  최대 메모리: %ld KB\n", mem_after);
    printf("  증가량: %ld KB\n", mem_after - mem_before);

    printf("\n");
    printf(COLOR_GREEN "=========================================================\n");
    printf("  벤치마크 완료!\n");
    printf("=========================================================\n" COLOR_RESET);
    printf("\n");

    return 0;
}
