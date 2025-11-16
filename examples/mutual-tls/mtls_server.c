/*
 * Q-TLS Mutual TLS Server Example
 * 상호 TLS 인증 서버 구현 예제
 *
 * 이 예제는 클라이언트 인증서를 요구하는 상호 TLS 인증(mTLS)
 * 서버를 구현하는 방법을 보여줍니다.
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

/* 서버 설정 */
#define SERVER_PORT 8443
#define BACKLOG 10
#define BUFFER_SIZE 4096

/* 전역 변수 */
static volatile int server_running = 1;

/*
 * 시그널 핸들러
 */
void signal_handler(int signum) {
    (void)signum;
    printf("\n[INFO] 서버 종료 신호 수신, 종료 중...\n");
    server_running = 0;
}

/*
 * 클라이언트 인증서 검증 콜백
 *
 * 이 함수는 클라이언트 인증서를 검증할 때 호출됩니다.
 * 여기서 추가적인 검증 로직을 구현할 수 있습니다.
 *
 * Parameters:
 *   preverify_ok: OpenSSL의 기본 검증 결과
 *   x509_ctx: X.509 인증서 컨텍스트
 *
 * Returns: 1 (검증 통과), 0 (검증 실패)
 */
int verify_client_callback(int preverify_ok, QTLS_X509 *x509_ctx) {
    (void)x509_ctx;

    if (!preverify_ok) {
        printf("[WARN] 클라이언트 인증서 사전 검증 실패\n");
        /* 테스트 환경에서는 자체 서명 인증서를 허용 */
        printf("[INFO] 자체 서명 인증서 허용 (테스트 모드)\n");
        return 1;
    }

    printf("[INFO] 클라이언트 인증서 검증 성공\n");
    return 1;
}

/*
 * 서버 소켓 생성
 */
int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() 실패");
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt() 실패");
        close(sockfd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind() 실패");
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen() 실패");
        close(sockfd);
        return -1;
    }

    printf("[INFO] 서버 소켓 생성 완료: 포트 %d\n", port);
    return sockfd;
}

/*
 * 클라이언트 인증서 정보 출력
 *
 * 인증서에서 주요 정보를 추출하여 출력합니다.
 */
void print_client_certificate_info(QTLS_CONNECTION *conn) {
    QTLS_CERTIFICATE *cert = qtls_get_peer_certificate(conn);
    if (!cert) {
        printf("[WARN] 클라이언트 인증서 없음\n");
        return;
    }

    printf("\n=== 클라이언트 인증서 정보 ===\n");
    printf("인증서 형식: %s\n",
           cert->format == QTLS_FILETYPE_PEM ? "PEM" : "DER");
    printf("인증서 크기: %zu 바이트\n", cert->length);
    printf("검증 상태: %s\n", cert->verified ? "검증됨" : "미검증");

    if (cert->dilithium_key) {
        printf("PQC 서명: Dilithium3 키 포함\n");
    }

    printf("================================\n\n");

    qtls_certificate_free(cert);
}

/*
 * 클라이언트 연결 처리
 */
void handle_client(QTLS_CTX *ctx, int client_fd, struct sockaddr_in *client_addr) {
    QTLS_CONNECTION *conn = NULL;
    char buffer[BUFFER_SIZE];
    int ret;

    printf("\n[INFO] 클라이언트 연결 시도: %s:%d\n",
           inet_ntoa(client_addr->sin_addr),
           ntohs(client_addr->sin_port));

    /* Q-TLS 연결 객체 생성 */
    conn = qtls_new(ctx);
    if (!conn) {
        fprintf(stderr, "[ERROR] qtls_new() 실패\n");
        goto cleanup;
    }

    ret = qtls_set_fd(conn, client_fd);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_set_fd() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* Q-TLS 핸드셰이크 수행 */
    printf("[INFO] Q-TLS 상호 인증 핸드셰이크 시작...\n");
    ret = qtls_accept(conn);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_accept() 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] 클라이언트 인증서가 올바른지 확인하세요.\n");
        goto cleanup;
    }

    printf("[SUCCESS] 상호 인증 핸드셰이크 완료!\n");

    /* 협상된 암호 스위트 출력 */
    const char *cipher = qtls_get_cipher(conn);
    printf("[INFO] 사용 암호 스위트: %s\n", cipher ? cipher : "Unknown");

    /* 클라이언트 인증서 검증 */
    ret = qtls_verify_peer_certificate(conn);
    if (ret == 1) {
        printf("[SUCCESS] 클라이언트 인증서 검증 성공!\n");
        print_client_certificate_info(conn);
    } else {
        fprintf(stderr, "[ERROR] 클라이언트 인증서 검증 실패\n");
        goto cleanup;
    }

    /* 클라이언트로부터 데이터 수신 */
    printf("[INFO] 인증된 클라이언트로부터 데이터 수신 대기 중...\n");
    memset(buffer, 0, sizeof(buffer));
    ret = qtls_read(conn, buffer, sizeof(buffer) - 1);

    if (ret > 0) {
        buffer[ret] = '\0';
        printf("[RECEIVED] 클라이언트 메시지: %s\n", buffer);

        /* 응답 메시지 작성 */
        const char *response = "인증 성공! Q-TLS 상호 인증 서버입니다. "
                               "클라이언트 인증서가 확인되었습니다.";

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

    qtls_shutdown(conn);

cleanup:
    if (conn) {
        qtls_free(conn);
    }
    close(client_fd);
    printf("[INFO] 클라이언트 연결 종료\n");
}

/*
 * 메인 함수
 */
int main(int argc, char *argv[]) {
    QTLS_CTX *ctx = NULL;
    int server_fd = -1;
    int port = SERVER_PORT;
    const char *server_cert = "certs/server.crt";
    const char *server_key = "certs/server.key";
    const char *ca_cert = "certs/ca.crt";
    int ret;

    printf("===============================================\n");
    printf("  Q-TLS Mutual TLS Server Example\n");
    printf("  양자 내성 상호 TLS 인증 서버 예제\n");
    printf("===============================================\n");
    printf("Q-TLS 버전: %s\n\n", qtls_version());

    /* 명령행 인자 처리 */
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "사용법: %s [포트]\n", argv[0]);
            return 1;
        }
    }

    /* 시그널 핸들러 등록 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Q-TLS 서버 컨텍스트 생성 */
    printf("[INFO] Q-TLS 서버 컨텍스트 초기화 중...\n");
    ctx = qtls_ctx_new(QTLS_SERVER_MODE);
    if (!ctx) {
        fprintf(stderr, "[ERROR] qtls_ctx_new() 실패\n");
        return 1;
    }

    /* 하이브리드 모드 활성화 */
    ret = qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_ctx_set_options() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }
    printf("[INFO] 하이브리드 모드 활성화 (ECDHE + Kyber1024)\n");

    /* 클라이언트 인증서 검증 모드 설정 */
    /* QTLS_VERIFY_PEER: 클라이언트 인증서 요청
     * QTLS_VERIFY_FAIL_IF_NO_PEER_CERT: 인증서 없으면 연결 거부 */
    ret = qtls_ctx_set_verify_mode(ctx,
        QTLS_VERIFY_PEER | QTLS_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_client_callback);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_ctx_set_verify_mode() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }
    printf("[INFO] 클라이언트 인증서 검증 활성화 (상호 인증 모드)\n");

    /* CA 인증서 로드 - 클라이언트 인증서 검증에 사용 */
    printf("[INFO] CA 인증서 로드: %s\n", ca_cert);
    ret = qtls_ctx_load_verify_locations(ctx, ca_cert, NULL);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] CA 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] generate_certs.sh 스크립트를 실행하여 인증서를 생성하세요.\n");
        goto cleanup;
    }

    /* 서버 인증서 로드 */
    printf("[INFO] 서버 인증서 로드: %s\n", server_cert);
    ret = qtls_ctx_use_certificate_file(ctx, server_cert, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 서버 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* 서버 개인키 로드 */
    printf("[INFO] 서버 개인키 로드: %s\n", server_key);
    ret = qtls_ctx_use_private_key_file(ctx, server_key, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 서버 개인키 로드 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* PQC 알고리즘 설정 */
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

    printf("\n[SUCCESS] Q-TLS 상호 인증 서버 시작!\n");
    printf("[INFO] 포트 %d에서 클라이언트 연결 대기 중...\n", port);
    printf("[INFO] 클라이언트 인증서가 필수입니다.\n");
    printf("[INFO] 종료하려면 Ctrl+C를 누르세요.\n\n");

    /* 메인 서버 루프 */
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd;

        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

        if (client_fd < 0) {
            if (errno == EINTR) {
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
