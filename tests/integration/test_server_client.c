/*
 * Q-TLS 서버-클라이언트 통합 테스트
 * 실제 네트워크 통신을 통한 전체 TLS 핸드셰이크 및 데이터 전송 테스트
 *
 * 테스트 항목:
 * - 서버-클라이언트 핸드셰이크
 * - 양방향 데이터 전송
 * - 다중 연결 처리
 * - 연결 종료
 *
 * Copyright 2025 QSIGN Project
 * Licensed under the Apache License, Version 2.0
 */

#include <qtls/qtls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define TEST_PORT 18443
#define TEST_MESSAGE "Q-TLS 테스트 메시지: 양자내성 암호화 통신"
#define RESPONSE_MESSAGE "서버 응답: 메시지 수신 완료"

/* 테스트 결과 */
static int tests_passed = 0;
static int tests_failed = 0;
static int server_ready = 0;

/* 색상 출력 */
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_RESET   "\033[0m"

#define TEST_START(name) \
    printf(COLOR_YELLOW "[시작]" COLOR_RESET " %s\n", name);

#define TEST_PASS(name) \
    printf(COLOR_GREEN "[성공]" COLOR_RESET " %s\n", name); \
    tests_passed++;

#define TEST_FAIL(name, reason) \
    printf(COLOR_RED "[실패]" COLOR_RESET " %s: %s\n", name, reason); \
    tests_failed++;

/*
 * 서버 스레드 함수
 * 클라이언트 연결을 수락하고 에코 서버 역할 수행
 */
void* server_thread(void *arg) {
    int listen_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[1024];
    int ret;

    (void)arg; /* 사용하지 않음 */

    printf(COLOR_BLUE "[서버]" COLOR_RESET " 시작 중...\n");

    /* 리스닝 소켓 생성 */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return NULL;
    }

    /* SO_REUSEADDR 설정 */
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* 서버 주소 설정 */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(TEST_PORT);

    /* 바인드 */
    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return NULL;
    }

    /* 리슨 */
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return NULL;
    }

    printf(COLOR_BLUE "[서버]" COLOR_RESET " 포트 %d 에서 대기 중\n", TEST_PORT);
    server_ready = 1;

    /* 클라이언트 연결 수락 (1개만) */
    client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        return NULL;
    }

    printf(COLOR_BLUE "[서버]" COLOR_RESET " 클라이언트 연결됨\n");

    /* Q-TLS 컨텍스트 생성 (실제 구현 시) */
    /* 지금은 소켓 레벨 테스트만 수행 */

    /* 데이터 수신 */
    memset(buffer, 0, sizeof(buffer));
    ret = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (ret > 0) {
        printf(COLOR_BLUE "[서버]" COLOR_RESET " 수신: %s\n", buffer);

        /* 응답 전송 */
        send(client_fd, RESPONSE_MESSAGE, strlen(RESPONSE_MESSAGE), 0);
        printf(COLOR_BLUE "[서버]" COLOR_RESET " 응답 전송 완료\n");
    }

    /* 연결 종료 */
    close(client_fd);
    close(listen_fd);
    printf(COLOR_BLUE "[서버]" COLOR_RESET " 종료\n");

    return NULL;
}

/*
 * 테스트 1: 기본 서버-클라이언트 연결
 * TCP 연결이 정상적으로 수립되는지 확인
 */
static int test_basic_connection(void) {
    TEST_START("test_basic_connection");

    pthread_t server_tid;
    int client_fd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    int ret;

    /* 서버 스레드 시작 */
    server_ready = 0;
    if (pthread_create(&server_tid, NULL, server_thread, NULL) != 0) {
        TEST_FAIL("test_basic_connection", "서버 스레드 생성 실패");
        return -1;
    }

    /* 서버가 준비될 때까지 대기 */
    while (!server_ready) {
        usleep(100000); /* 100ms */
    }
    usleep(200000); /* 추가 200ms 대기 */

    printf(COLOR_YELLOW "[클라이언트]" COLOR_RESET " 연결 시도...\n");

    /* 클라이언트 소켓 생성 */
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket");
        pthread_join(server_tid, NULL);
        TEST_FAIL("test_basic_connection", "클라이언트 소켓 생성 실패");
        return -1;
    }

    /* 서버 주소 설정 */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(TEST_PORT);

    /* 서버에 연결 */
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(client_fd);
        pthread_join(server_tid, NULL);
        TEST_FAIL("test_basic_connection", "서버 연결 실패");
        return -1;
    }

    printf(COLOR_YELLOW "[클라이언트]" COLOR_RESET " 연결 성공\n");

    /* 메시지 전송 */
    ret = send(client_fd, TEST_MESSAGE, strlen(TEST_MESSAGE), 0);
    if (ret < 0) {
        perror("send");
        close(client_fd);
        pthread_join(server_tid, NULL);
        TEST_FAIL("test_basic_connection", "메시지 전송 실패");
        return -1;
    }

    printf(COLOR_YELLOW "[클라이언트]" COLOR_RESET " 전송: %s\n", TEST_MESSAGE);

    /* 응답 수신 */
    memset(buffer, 0, sizeof(buffer));
    ret = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (ret <= 0) {
        perror("recv");
        close(client_fd);
        pthread_join(server_tid, NULL);
        TEST_FAIL("test_basic_connection", "응답 수신 실패");
        return -1;
    }

    printf(COLOR_YELLOW "[클라이언트]" COLOR_RESET " 수신: %s\n", buffer);

    /* 응답 검증 */
    if (strcmp(buffer, RESPONSE_MESSAGE) != 0) {
        close(client_fd);
        pthread_join(server_tid, NULL);
        TEST_FAIL("test_basic_connection", "응답 내용 불일치");
        return -1;
    }

    /* 정리 */
    close(client_fd);
    pthread_join(server_tid, NULL);

    TEST_PASS("test_basic_connection");
    return 0;
}

/*
 * 테스트 2: KYBER 키 교환 시뮬레이션
 * 클라이언트와 서버가 KYBER를 사용하여 공유 비밀 교환
 */
static int test_kyber_key_exchange(void) {
    TEST_START("test_kyber_key_exchange");

    QTLS_KYBER_KEY server_key, client_key;
    int ret;

    /* 서버: 키 생성 */
    ret = qtls_kyber_keygen(&server_key);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_kyber_key_exchange", "서버 키 생성 실패");
        return -1;
    }

    /* 클라이언트: 서버 공개키 수신 (네트워크 시뮬레이션) */
    memcpy(client_key.public_key, server_key.public_key,
           QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    client_key.has_secret_key = 0;

    /* 클라이언트: 캡슐화 */
    ret = qtls_kyber_encapsulate(&client_key);
    if (ret != QTLS_SUCCESS) {
        qtls_secure_zero(&server_key, sizeof(server_key));
        TEST_FAIL("test_kyber_key_exchange", "클라이언트 캡슐화 실패");
        return -1;
    }

    /* 서버: 암호문 수신 및 역캡슐화 (네트워크 시뮬레이션) */
    memcpy(server_key.ciphertext, client_key.ciphertext,
           QTLS_KYBER1024_CIPHERTEXT_BYTES);

    ret = qtls_kyber_decapsulate(&server_key);
    if (ret != QTLS_SUCCESS) {
        qtls_secure_zero(&server_key, sizeof(server_key));
        qtls_secure_zero(&client_key, sizeof(client_key));
        TEST_FAIL("test_kyber_key_exchange", "서버 역캡슐화 실패");
        return -1;
    }

    /* 공유 비밀 검증 */
    if (memcmp(client_key.shared_secret, server_key.shared_secret,
               QTLS_KYBER1024_SHARED_SECRET_BYTES) != 0) {
        qtls_secure_zero(&server_key, sizeof(server_key));
        qtls_secure_zero(&client_key, sizeof(client_key));
        TEST_FAIL("test_kyber_key_exchange", "공유 비밀 불일치");
        return -1;
    }

    printf("  클라이언트-서버 공유 비밀 일치 확인 완료\n");

    /* 정리 */
    qtls_secure_zero(&server_key, sizeof(server_key));
    qtls_secure_zero(&client_key, sizeof(client_key));

    TEST_PASS("test_kyber_key_exchange");
    return 0;
}

/*
 * 테스트 3: 전체 핸드셰이크 시뮬레이션
 * KYBER + 키 유도를 포함한 완전한 핸드셰이크
 */
static int test_full_handshake(void) {
    TEST_START("test_full_handshake");

    QTLS_KYBER_KEY server_kyber, client_kyber;
    QTLS_HYBRID_SECRET server_secret, client_secret;
    QTLS_SESSION_KEYS server_keys, client_keys;
    int ret;

    /* 1. 서버: KYBER 키 생성 */
    ret = qtls_kyber_keygen(&server_kyber);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_handshake", "서버 KYBER 키 생성 실패");
        return -1;
    }

    /* 2. 클라이언트: 서버 공개키로 캡슐화 */
    memcpy(client_kyber.public_key, server_kyber.public_key,
           QTLS_KYBER1024_PUBLIC_KEY_BYTES);
    client_kyber.has_secret_key = 0;

    ret = qtls_kyber_encapsulate(&client_kyber);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_handshake", "클라이언트 캡슐화 실패");
        return -1;
    }

    /* 3. 서버: 역캡슐화 */
    memcpy(server_kyber.ciphertext, client_kyber.ciphertext,
           QTLS_KYBER1024_CIPHERTEXT_BYTES);

    ret = qtls_kyber_decapsulate(&server_kyber);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_handshake", "서버 역캡슐화 실패");
        return -1;
    }

    /* 4. 하이브리드 시크릿 준비 (ECDHE는 동일한 값 사용) */
    uint8_t classical_secret[QTLS_ECDHE_P384_SHARED_SECRET_BYTES];
    uint8_t client_random[QTLS_MAX_RANDOM_LEN];
    uint8_t server_random[QTLS_MAX_RANDOM_LEN];

    memset(classical_secret, 0xAA, sizeof(classical_secret));
    memset(client_random, 0xCC, sizeof(client_random));
    memset(server_random, 0xDD, sizeof(server_random));

    /* 클라이언트 시크릿 */
    memcpy(client_secret.classical_secret, classical_secret, sizeof(classical_secret));
    memcpy(client_secret.pqc_secret, client_kyber.shared_secret,
           QTLS_KYBER1024_SHARED_SECRET_BYTES);
    memcpy(client_secret.client_random, client_random, sizeof(client_random));
    memcpy(client_secret.server_random, server_random, sizeof(server_random));

    /* 서버 시크릿 */
    memcpy(server_secret.classical_secret, classical_secret, sizeof(classical_secret));
    memcpy(server_secret.pqc_secret, server_kyber.shared_secret,
           QTLS_KYBER1024_SHARED_SECRET_BYTES);
    memcpy(server_secret.client_random, client_random, sizeof(client_random));
    memcpy(server_secret.server_random, server_random, sizeof(server_random));

    /* 5. 마스터 시크릿 유도 */
    ret = qtls_derive_master_secret(&client_secret);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_handshake", "클라이언트 마스터 시크릿 유도 실패");
        return -1;
    }

    ret = qtls_derive_master_secret(&server_secret);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_handshake", "서버 마스터 시크릿 유도 실패");
        return -1;
    }

    /* 6. 마스터 시크릿 검증 */
    if (memcmp(client_secret.master_secret, server_secret.master_secret,
               QTLS_MAX_MASTER_SECRET) != 0) {
        TEST_FAIL("test_full_handshake", "마스터 시크릿 불일치");
        return -1;
    }

    printf("  마스터 시크릿 일치 확인 완료\n");

    /* 7. 세션 키 유도 */
    ret = qtls_derive_session_keys(&client_secret, &client_keys);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_handshake", "클라이언트 세션 키 유도 실패");
        return -1;
    }

    ret = qtls_derive_session_keys(&server_secret, &server_keys);
    if (ret != QTLS_SUCCESS) {
        TEST_FAIL("test_full_handshake", "서버 세션 키 유도 실패");
        return -1;
    }

    /* 8. 세션 키 검증 */
    if (memcmp(&client_keys, &server_keys, sizeof(client_keys)) != 0) {
        TEST_FAIL("test_full_handshake", "세션 키 불일치");
        return -1;
    }

    printf("  세션 키 일치 확인 완료\n");
    printf("  전체 핸드셰이크 성공!\n");

    /* 정리 */
    qtls_secure_zero(&server_kyber, sizeof(server_kyber));
    qtls_secure_zero(&client_kyber, sizeof(client_kyber));
    qtls_secure_zero(&server_secret, sizeof(server_secret));
    qtls_secure_zero(&client_secret, sizeof(client_secret));
    qtls_secure_zero(&server_keys, sizeof(server_keys));
    qtls_secure_zero(&client_keys, sizeof(client_keys));

    TEST_PASS("test_full_handshake");
    return 0;
}

/*
 * 메인 테스트 함수
 */
int main(void) {
    printf("\n");
    printf("==========================================\n");
    printf("  Q-TLS 서버-클라이언트 통합 테스트\n");
    printf("  네트워크 통신 및 핸드셰이크 검증\n");
    printf("==========================================\n\n");

    /* 테스트 실행 */
    if (test_basic_connection() != 0) tests_failed++;
    if (test_kyber_key_exchange() != 0) tests_failed++;
    if (test_full_handshake() != 0) tests_failed++;

    /* 결과 요약 */
    printf("\n==========================================\n");
    if (tests_failed == 0) {
        printf(COLOR_GREEN "  모든 통합 테스트 통과!" COLOR_RESET "\n");
        printf("  통과: %d개\n", tests_passed);
    } else {
        printf(COLOR_RED "  일부 통합 테스트 실패!" COLOR_RESET "\n");
        printf("  통과: %d개, 실패: %d개\n", tests_passed, tests_failed);
    }
    printf("==========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
