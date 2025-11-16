/*
 * Q-TLS Simple Server Example
 * 간단한 Q-TLS 서버 구현 예제
 *
 * 이 예제는 기본적인 Q-TLS 서버를 구현하는 방법을 보여줍니다.
 * 양자 내성 암호화(PQC)와 기존 암호화를 결합한 하이브리드 모드로 동작합니다.
 *
 * Copyright 2025 QSIGN Project
 * Licensed under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <qtls/qtls.h>

/* 서버 설정 상수 */
#define SERVER_PORT 8443
#define BACKLOG 10
#define BUFFER_SIZE 4096

/* 전역 변수: 시그널 핸들러에서 사용 */
static volatile int server_running = 1;

/*
 * 시그널 핸들러
 * SIGINT (Ctrl+C) 또는 SIGTERM 수신 시 서버를 우아하게 종료합니다.
 */
void signal_handler(int signum) {
    (void)signum;
    printf("\n[INFO] 서버 종료 신호 수신, 종료 중...\n");
    server_running = 0;
}

/*
 * 서버 소켓 생성 및 바인딩
 *
 * Returns: 성공 시 소켓 파일 디스크립터, 실패 시 -1
 */
int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    /* TCP 소켓 생성 */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() 실패");
        return -1;
    }

    /* SO_REUSEADDR 옵션 설정: 서버 재시작 시 즉시 포트 재사용 가능 */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt() 실패");
        close(sockfd);
        return -1;
    }

    /* 주소 구조체 초기화 */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  /* 모든 인터페이스에서 수신 */
    addr.sin_port = htons(port);

    /* 소켓에 주소 바인딩 */
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind() 실패");
        close(sockfd);
        return -1;
    }

    /* 연결 대기 큐 설정 */
    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen() 실패");
        close(sockfd);
        return -1;
    }

    printf("[INFO] 서버 소켓 생성 완료: 포트 %d\n", port);
    return sockfd;
}

/*
 * 클라이언트 연결 처리
 *
 * 이 함수는 각 클라이언트와의 Q-TLS 핸드셰이크를 수행하고
 * 보안 채널을 통해 데이터를 교환합니다.
 *
 * Parameters:
 *   ctx: Q-TLS 컨텍스트
 *   client_fd: 클라이언트 소켓 파일 디스크립터
 *   client_addr: 클라이언트 주소 정보
 */
void handle_client(QTLS_CTX *ctx, int client_fd, struct sockaddr_in *client_addr) {
    QTLS_CONNECTION *conn = NULL;
    char buffer[BUFFER_SIZE];
    int ret;

    printf("[INFO] 클라이언트 연결: %s:%d\n",
           inet_ntoa(client_addr->sin_addr),
           ntohs(client_addr->sin_port));

    /* Q-TLS 연결 객체 생성 */
    conn = qtls_new(ctx);
    if (!conn) {
        fprintf(stderr, "[ERROR] qtls_new() 실패\n");
        goto cleanup;
    }

    /* 소켓 파일 디스크립터 연결 */
    ret = qtls_set_fd(conn, client_fd);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_set_fd() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* Q-TLS 핸드셰이크 수행 (서버 측) */
    printf("[INFO] Q-TLS 핸드셰이크 시작...\n");
    ret = qtls_accept(conn);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_accept() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* 핸드셰이크 성공 - 협상된 암호 스위트 출력 */
    const char *cipher = qtls_get_cipher(conn);
    printf("[SUCCESS] Q-TLS 핸드셰이크 완료\n");
    printf("[INFO] 사용 암호 스위트: %s\n", cipher ? cipher : "Unknown");

    /* 클라이언트로부터 데이터 수신 */
    printf("[INFO] 클라이언트로부터 데이터 수신 대기 중...\n");
    ret = qtls_read(conn, buffer, sizeof(buffer) - 1);
    if (ret > 0) {
        buffer[ret] = '\0';
        printf("[RECEIVED] 클라이언트 메시지: %s\n", buffer);

        /* 응답 메시지 작성 */
        const char *response = "안녕하세요! Q-TLS 서버입니다. 메시지를 정상적으로 수신했습니다.";

        /* 응답 전송 */
        ret = qtls_write(conn, response, strlen(response));
        if (ret > 0) {
            printf("[SENT] 응답 전송 완료: %d 바이트\n", ret);
        } else {
            fprintf(stderr, "[ERROR] qtls_write() 실패: %s\n",
                    qtls_get_error_string(ret));
        }
    } else if (ret == 0) {
        printf("[INFO] 클라이언트가 연결을 종료했습니다.\n");
    } else {
        fprintf(stderr, "[ERROR] qtls_read() 실패: %s\n",
                qtls_get_error_string(ret));
    }

    /* Q-TLS 연결 종료 */
    qtls_shutdown(conn);

cleanup:
    if (conn) {
        qtls_free(conn);
    }
    close(client_fd);
    printf("[INFO] 클라이언트 연결 종료\n\n");
}

/*
 * 메인 함수
 */
int main(int argc, char *argv[]) {
    QTLS_CTX *ctx = NULL;
    int server_fd = -1;
    int port = SERVER_PORT;
    const char *cert_file = "server.crt";
    const char *key_file = "server.key";
    int ret;

    /* 명령행 인자 처리 */
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "사용법: %s [포트] [인증서] [개인키]\n", argv[0]);
            fprintf(stderr, "  포트: 1-65535 범위의 포트 번호 (기본값: 8443)\n");
            return 1;
        }
    }
    if (argc >= 3) {
        cert_file = argv[2];
    }
    if (argc >= 4) {
        key_file = argv[3];
    }

    printf("===========================================\n");
    printf("  Q-TLS Simple Server Example\n");
    printf("  양자 내성 TLS 서버 예제\n");
    printf("===========================================\n");
    printf("Q-TLS 버전: %s\n\n", qtls_version());

    /* 시그널 핸들러 등록 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Q-TLS 컨텍스트 생성 (서버 모드) */
    printf("[INFO] Q-TLS 서버 컨텍스트 초기화 중...\n");
    ctx = qtls_ctx_new(QTLS_SERVER_MODE);
    if (!ctx) {
        fprintf(stderr, "[ERROR] qtls_ctx_new() 실패\n");
        return 1;
    }

    /* 하이브리드 모드 활성화 (고전 암호화 + PQC) */
    ret = qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_ctx_set_options() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }
    printf("[INFO] 하이브리드 모드 활성화 (ECDHE + Kyber1024)\n");

    /* 서버 인증서 로드 */
    printf("[INFO] 서버 인증서 로드: %s\n", cert_file);
    ret = qtls_ctx_use_certificate_file(ctx, cert_file, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] generate_certs.sh 스크립트를 실행하여 인증서를 생성하세요.\n");
        goto cleanup;
    }

    /* 서버 개인키 로드 */
    printf("[INFO] 서버 개인키 로드: %s\n", key_file);
    ret = qtls_ctx_use_private_key_file(ctx, key_file, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 개인키 로드 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* 지원하는 PQC 알고리즘 설정 */
    uint16_t kems[] = {QTLS_KEM_KYBER1024};
    uint16_t sigs[] = {QTLS_SIG_DILITHIUM3};
    ret = qtls_ctx_set_pqc_algorithms(ctx, kems, 1, sigs, 1);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] PQC 알고리즘 설정 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }
    printf("[INFO] PQC 알고리즘: Kyber1024 (KEM), Dilithium3 (Signature)\n");

    /* 서버 소켓 생성 */
    server_fd = create_server_socket(port);
    if (server_fd < 0) {
        fprintf(stderr, "[ERROR] 서버 소켓 생성 실패\n");
        goto cleanup;
    }

    printf("\n[SUCCESS] Q-TLS 서버 시작!\n");
    printf("[INFO] 포트 %d에서 클라이언트 연결 대기 중...\n", port);
    printf("[INFO] 종료하려면 Ctrl+C를 누르세요.\n\n");

    /* 메인 서버 루프 */
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd;

        /* 클라이언트 연결 수락 (타임아웃 설정을 통해 시그널 확인 가능) */
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

        if (client_fd < 0) {
            if (errno == EINTR) {
                /* 시그널에 의한 중단 - 정상 */
                continue;
            }
            perror("accept() 실패");
            continue;
        }

        /* 클라이언트 연결 처리 */
        handle_client(ctx, client_fd, &client_addr);
    }

    printf("\n[INFO] 서버 종료 중...\n");

cleanup:
    if (server_fd >= 0) {
        close(server_fd);
    }
    if (ctx) {
        qtls_ctx_free(ctx);
    }

    printf("[INFO] 서버 종료 완료\n");
    return 0;
}
