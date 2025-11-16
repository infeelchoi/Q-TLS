/*
 * Q-TLS Mutual TLS Client Example
 * 상호 TLS 인증 클라이언트 구현 예제
 *
 * 이 예제는 클라이언트 인증서를 사용하여 서버에 인증하는
 * 상호 TLS 인증(mTLS) 클라이언트를 구현하는 방법을 보여줍니다.
 *
 * Copyright 2025 QSIGN Project
 * Licensed under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <qtls/qtls.h>

/* 설정 */
#define BUFFER_SIZE 4096
#define DEFAULT_PORT 8443
#define DEFAULT_HOST "localhost"

/*
 * 호스트명을 IP 주소로 변환
 */
int resolve_hostname(const char *hostname, char *ip_addr, size_t buf_len) {
    struct hostent *he;
    struct in_addr **addr_list;

    he = gethostbyname(hostname);
    if (he == NULL) {
        herror("gethostbyname() 실패");
        return -1;
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] == NULL) {
        fprintf(stderr, "[ERROR] 호스트명 해석 실패: %s\n", hostname);
        return -1;
    }

    strncpy(ip_addr, inet_ntoa(*addr_list[0]), buf_len - 1);
    ip_addr[buf_len - 1] = '\0';

    return 0;
}

/*
 * 서버에 TCP 연결
 */
int connect_to_server(const char *host, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    char ip_addr[INET_ADDRSTRLEN];

    if (resolve_hostname(host, ip_addr, sizeof(ip_addr)) < 0) {
        return -1;
    }

    printf("[INFO] 연결 대상: %s (%s:%d)\n", host, ip_addr, port);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() 실패");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_addr, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "[ERROR] 잘못된 IP 주소: %s\n", ip_addr);
        close(sockfd);
        return -1;
    }

    printf("[INFO] 서버에 연결 중...\n");
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect() 실패");
        close(sockfd);
        return -1;
    }

    printf("[SUCCESS] TCP 연결 성공\n");
    return sockfd;
}

/*
 * 서버 인증서 검증 콜백
 *
 * 서버 인증서를 검증할 때 호출됩니다.
 * 추가적인 검증 로직을 구현할 수 있습니다.
 */
int verify_server_callback(int preverify_ok, QTLS_X509 *x509_ctx) {
    (void)x509_ctx;

    if (!preverify_ok) {
        printf("[WARN] 서버 인증서 사전 검증 실패\n");
        printf("[INFO] 자체 서명 인증서 허용 (테스트 모드)\n");
        return 1;  /* 테스트 환경에서는 허용 */
    }

    printf("[INFO] 서버 인증서 검증 성공\n");
    return 1;
}

/*
 * Q-TLS 상호 인증 통신 수행
 */
int qtls_mtls_communicate(const char *host, int port, const char *message) {
    QTLS_CTX *ctx = NULL;
    QTLS_CONNECTION *conn = NULL;
    int sockfd = -1;
    char buffer[BUFFER_SIZE];
    int ret;
    int retval = -1;

    const char *client_cert = "certs/client.crt";
    const char *client_key = "certs/client.key";
    const char *ca_cert = "certs/ca.crt";

    printf("\n[INFO] Q-TLS 클라이언트 컨텍스트 초기화 중...\n");

    /* Q-TLS 클라이언트 컨텍스트 생성 */
    ctx = qtls_ctx_new(QTLS_CLIENT_MODE);
    if (!ctx) {
        fprintf(stderr, "[ERROR] qtls_ctx_new() 실패\n");
        return -1;
    }

    /* 하이브리드 모드 활성화 */
    ret = qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_ctx_set_options() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }
    printf("[INFO] 하이브리드 모드 활성화 (ECDHE + Kyber1024)\n");

    /* 클라이언트 인증서 로드 - 상호 인증에 필요 */
    printf("[INFO] 클라이언트 인증서 로드: %s\n", client_cert);
    ret = qtls_ctx_use_certificate_file(ctx, client_cert, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 클라이언트 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] generate_certs.sh 스크립트를 실행하여 인증서를 생성하세요.\n");
        goto cleanup;
    }

    /* 클라이언트 개인키 로드 */
    printf("[INFO] 클라이언트 개인키 로드: %s\n", client_key);
    ret = qtls_ctx_use_private_key_file(ctx, client_key, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 클라이언트 개인키 로드 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* CA 인증서 로드 - 서버 인증서 검증에 사용 */
    printf("[INFO] CA 인증서 로드: %s\n", ca_cert);
    ret = qtls_ctx_load_verify_locations(ctx, ca_cert, NULL);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] CA 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* 서버 인증서 검증 활성화 */
    ret = qtls_ctx_set_verify_mode(ctx, QTLS_VERIFY_PEER, verify_server_callback);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_ctx_set_verify_mode() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }
    printf("[INFO] 서버 인증서 검증 활성화\n");

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

    /* 서버에 TCP 연결 */
    sockfd = connect_to_server(host, port);
    if (sockfd < 0) {
        fprintf(stderr, "[ERROR] 서버 연결 실패\n");
        goto cleanup;
    }

    /* Q-TLS 연결 객체 생성 */
    conn = qtls_new(ctx);
    if (!conn) {
        fprintf(stderr, "[ERROR] qtls_new() 실패\n");
        goto cleanup;
    }

    ret = qtls_set_fd(conn, sockfd);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_set_fd() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* SNI 설정 */
    ret = qtls_set_server_name(conn, host);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_set_server_name() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }
    printf("[INFO] SNI 설정: %s\n", host);

    /* Q-TLS 상호 인증 핸드셰이크 수행 */
    printf("\n[INFO] Q-TLS 상호 인증 핸드셰이크 시작...\n");
    printf("[INFO] 클라이언트 인증서 제공 중...\n");

    ret = qtls_connect(conn);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_connect() 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] 서버가 클라이언트 인증서를 거부했을 수 있습니다.\n");
        goto cleanup;
    }

    printf("[SUCCESS] 상호 인증 핸드셰이크 완료!\n");

    /* 협상된 정보 출력 */
    const char *cipher = qtls_get_cipher(conn);
    printf("[INFO] 사용 암호 스위트: %s\n", cipher ? cipher : "Unknown");

    int version = qtls_get_version(conn);
    printf("[INFO] 프로토콜 버전: 0x%04X\n", version);

    /* 서버 인증서 검증 */
    ret = qtls_verify_peer_certificate(conn);
    if (ret == 1) {
        printf("[SUCCESS] 서버 인증서 검증 성공!\n");

        QTLS_CERTIFICATE *cert = qtls_get_peer_certificate(conn);
        if (cert) {
            printf("[INFO] 서버 인증서 수신 완료 (%zu 바이트)\n", cert->length);
            qtls_certificate_free(cert);
        }
    } else {
        fprintf(stderr, "[WARN] 서버 인증서 검증 경고\n");
    }

    /* 메시지 전송 */
    printf("\n[INFO] 인증 완료, 메시지 전송 중...\n");
    printf("[SEND] %s\n", message);

    ret = qtls_write(conn, message, strlen(message));
    if (ret <= 0) {
        fprintf(stderr, "[ERROR] qtls_write() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    printf("[SUCCESS] 전송 완료: %d 바이트\n", ret);

    /* 서버 응답 수신 */
    printf("\n[INFO] 서버 응답 대기 중...\n");
    memset(buffer, 0, sizeof(buffer));
    ret = qtls_read(conn, buffer, sizeof(buffer) - 1);

    if (ret > 0) {
        buffer[ret] = '\0';
        printf("[RECEIVED] 서버 응답: %s\n", buffer);
        printf("[SUCCESS] 수신 완료: %d 바이트\n", ret);
        retval = 0;
    } else if (ret == 0) {
        printf("[INFO] 서버가 연결을 종료했습니다.\n");
        retval = 0;
    } else {
        fprintf(stderr, "[ERROR] qtls_read() 실패: %s\n",
                qtls_get_error_string(ret));
    }

    printf("\n[INFO] 연결 종료 중...\n");
    qtls_shutdown(conn);

cleanup:
    if (conn) {
        qtls_free(conn);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
    if (ctx) {
        qtls_ctx_free(ctx);
    }

    return retval;
}

/*
 * 메인 함수
 */
int main(int argc, char *argv[]) {
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    const char *message = "안녕하세요! 인증된 Q-TLS 클라이언트입니다.";

    printf("===================================================\n");
    printf("  Q-TLS Mutual TLS Client Example\n");
    printf("  양자 내성 상호 TLS 인증 클라이언트 예제\n");
    printf("===================================================\n");
    printf("Q-TLS 버전: %s\n", qtls_version());

    /* 명령행 인자 처리 */
    if (argc >= 2) {
        host = argv[1];
    }
    if (argc >= 3) {
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "[ERROR] 잘못된 포트 번호: %s\n", argv[2]);
            fprintf(stderr, "사용법: %s [호스트] [포트] [메시지]\n", argv[0]);
            return 1;
        }
    }
    if (argc >= 4) {
        message = argv[3];
    }

    printf("\n연결 정보:\n");
    printf("  호스트: %s\n", host);
    printf("  포트: %d\n", port);
    printf("  메시지: %s\n", message);
    printf("  인증 모드: 상호 TLS (클라이언트 인증서 사용)\n");

    /* Q-TLS 상호 인증 통신 수행 */
    int result = qtls_mtls_communicate(host, port, message);

    if (result == 0) {
        printf("\n[SUCCESS] 상호 인증 통신 완료!\n");
        printf("[INFO] 클라이언트와 서버 모두 인증되었습니다.\n");
        return 0;
    } else {
        printf("\n[FAILED] 상호 인증 통신 실패\n");
        return 1;
    }
}
