/*
 * Q-TLS QSIGN Integration Server Example
 * QSIGN PKI 및 HSM 통합 서버 구현 예제
 *
 * 이 예제는 QSIGN PKI 시스템과 Luna HSM을 통합한
 * 엔터프라이즈급 Q-TLS 서버를 구현하는 방법을 보여줍니다.
 *
 * 주요 기능:
 * - Luna HSM을 통한 개인키 관리
 * - QSIGN PKI 인증서 체인 검증
 * - 상호 TLS 인증
 * - 세션 관리 및 로깅
 * - 성능 모니터링
 *
 * Copyright 2025 QSIGN Project
 * Licensed under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <qtls/qtls.h>

/* 서버 설정 */
#define SERVER_PORT 8443
#define BACKLOG 128
#define BUFFER_SIZE 8192
#define MAX_SESSIONS 1000

/* HSM 설정 */
#define HSM_MODULE_PATH "/usr/lib/libCryptoki2_64.so"  // Luna HSM
#define HSM_TOKEN_LABEL "qsign-server"
#define HSM_KEY_LABEL "server-key"

/* QSIGN PKI 설정 */
#define QSIGN_CA_CERT "/etc/qsign/ca/root-ca.crt"
#define QSIGN_INTERMEDIATE_CA "/etc/qsign/ca/intermediate-ca.crt"
#define QSIGN_SERVER_CERT "/etc/qsign/certs/server.crt"
#define QSIGN_CRL_PATH "/etc/qsign/crl"

/* 전역 변수 */
static volatile int server_running = 1;
static unsigned long session_counter = 0;
static unsigned long total_bytes_received = 0;
static unsigned long total_bytes_sent = 0;

/* 세션 통계 구조체 */
typedef struct {
    unsigned long session_id;
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
    time_t start_time;
    time_t end_time;
    size_t bytes_received;
    size_t bytes_sent;
    char cipher[256];
    int authenticated;
} session_stats_t;

/*
 * 시그널 핸들러
 */
void signal_handler(int signum) {
    (void)signum;
    printf("\n[INFO] 서버 종료 신호 수신, 우아한 종료 시작...\n");
    server_running = 0;
}

/*
 * 현재 시각 문자열 반환
 */
void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/*
 * 보안 감사 로그 기록
 *
 * 모든 보안 이벤트를 기록합니다.
 */
void audit_log(const char *event, const char *client_ip, int client_port,
               const char *details) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    printf("[AUDIT] %s | %s:%d | %s | %s\n",
           timestamp, client_ip, client_port, event, details);

    /* 프로덕션: syslog 또는 중앙 로그 서버로 전송 */
    // syslog(LOG_INFO, "QTLS_AUDIT: %s | %s:%d | %s | %s",
    //        timestamp, client_ip, client_port, event, details);
}

/*
 * 클라이언트 인증서 검증 콜백
 *
 * QSIGN PKI 정책에 따라 클라이언트 인증서를 엄격하게 검증합니다.
 */
int verify_client_callback(int preverify_ok, QTLS_X509 *x509_ctx) {
    (void)x509_ctx;

    if (!preverify_ok) {
        printf("[SECURITY] 클라이언트 인증서 검증 실패\n");

        /* 프로덕션 환경: 검증 실패 시 연결 거부 */
        #ifdef PRODUCTION_MODE
        return 0;
        #else
        printf("[WARN] 테스트 모드: 검증 실패 허용\n");
        return 1;
        #endif
    }

    printf("[INFO] 클라이언트 인증서 검증 성공\n");
    return 1;
}

/*
 * HSM 초기화
 *
 * Luna HSM을 초기화하고 로그인합니다.
 */
int initialize_hsm(const char *pin) {
    int ret;

    printf("[INFO] Luna HSM 초기화 중...\n");
    printf("[INFO] HSM 모듈: %s\n", HSM_MODULE_PATH);

    ret = qtls_hsm_init(HSM_MODULE_PATH);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] HSM 초기화 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] Luna HSM이 설치되어 있고 접근 가능한지 확인하세요.\n");
        return ret;
    }

    printf("[INFO] HSM 로그인 중... (토큰: %s)\n", HSM_TOKEN_LABEL);
    ret = qtls_hsm_login(HSM_TOKEN_LABEL, pin);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] HSM 로그인 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] HSM PIN을 확인하세요.\n");
        qtls_hsm_cleanup();
        return ret;
    }

    printf("[SUCCESS] Luna HSM 초기화 완료\n");
    return QTLS_SUCCESS;
}

/*
 * QSIGN PKI 컨텍스트 설정
 */
int setup_qsign_pki(QTLS_CTX *ctx, int use_hsm, const char *server_key_path) {
    int ret;

    /* 하이브리드 PQC 모드 활성화 */
    ret = qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 하이브리드 모드 활성화 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }
    printf("[INFO] 하이브리드 PQC 모드 활성화\n");

    /* 클라이언트 인증서 검증 모드 설정 */
    ret = qtls_ctx_set_verify_mode(ctx,
        QTLS_VERIFY_PEER | QTLS_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_client_callback);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 검증 모드 설정 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }
    printf("[INFO] 상호 TLS 인증 활성화 (클라이언트 인증서 필수)\n");

    /* QSIGN CA 인증서 로드 */
    printf("[INFO] QSIGN CA 인증서 로드 중...\n");
    ret = qtls_ctx_load_verify_locations(ctx, QSIGN_CA_CERT, QSIGN_CRL_PATH);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] CA 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        fprintf(stderr, "[HINT] QSIGN PKI가 올바르게 설정되어 있는지 확인하세요.\n");
        return ret;
    }
    printf("[INFO] QSIGN Root CA 로드 완료\n");

    /* 서버 인증서 로드 */
    printf("[INFO] 서버 인증서 로드: %s\n", QSIGN_SERVER_CERT);
    ret = qtls_ctx_use_certificate_file(ctx, QSIGN_SERVER_CERT, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 서버 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }

    /* 서버 개인키 로드 (HSM 또는 파일) */
    if (use_hsm) {
        /* Luna HSM에서 개인키 사용 */
        char hsm_uri[256];
        snprintf(hsm_uri, sizeof(hsm_uri),
                 "pkcs11:token=%s;object=%s",
                 HSM_TOKEN_LABEL, HSM_KEY_LABEL);

        printf("[INFO] HSM에서 개인키 로드: %s\n", hsm_uri);
        ret = qtls_ctx_use_hsm_key(ctx, hsm_uri);
        if (ret != QTLS_SUCCESS) {
            fprintf(stderr, "[ERROR] HSM 개인키 로드 실패: %s\n",
                    qtls_get_error_string(ret));
            fprintf(stderr, "[HINT] HSM에 '%s' 키가 존재하는지 확인하세요.\n",
                    HSM_KEY_LABEL);
            return ret;
        }
        printf("[SUCCESS] HSM 개인키 로드 완료 (하드웨어 보안)\n");
    } else {
        /* 파일에서 개인키 로드 (테스트용) */
        printf("[WARN] 파일에서 개인키 로드 (테스트 모드)\n");
        printf("[INFO] 개인키: %s\n", server_key_path);
        ret = qtls_ctx_use_private_key_file(ctx, server_key_path, QTLS_FILETYPE_PEM);
        if (ret != QTLS_SUCCESS) {
            fprintf(stderr, "[ERROR] 개인키 로드 실패: %s\n",
                    qtls_get_error_string(ret));
            return ret;
        }
    }

    /* PQC 알고리즘 설정 */
    uint16_t kems[] = {QTLS_KEM_KYBER1024, QTLS_KEM_ECDHE_P384};
    uint16_t sigs[] = {QTLS_SIG_DILITHIUM3, QTLS_SIG_ECDSA_P384};
    ret = qtls_ctx_set_pqc_algorithms(ctx, kems, 2, sigs, 2);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] PQC 알고리즘 설정 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }
    printf("[INFO] PQC 알고리즘 설정: Kyber1024+ECDHE, Dilithium3+ECDSA\n");

    return QTLS_SUCCESS;
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

    printf("[INFO] 서버 소켓 생성 완료: 포트 %d (백로그: %d)\n", port, BACKLOG);
    return sockfd;
}

/*
 * 클라이언트 세션 처리
 */
void handle_client_session(QTLS_CTX *ctx, int client_fd,
                           struct sockaddr_in *client_addr) {
    QTLS_CONNECTION *conn = NULL;
    char buffer[BUFFER_SIZE];
    session_stats_t stats;
    int ret;

    /* 세션 통계 초기화 */
    memset(&stats, 0, sizeof(stats));
    stats.session_id = ++session_counter;
    strncpy(stats.client_ip, inet_ntoa(client_addr->sin_addr),
            sizeof(stats.client_ip));
    stats.client_port = ntohs(client_addr->sin_port);
    stats.start_time = time(NULL);

    printf("\n========== 세션 #%lu 시작 ==========\n", stats.session_id);
    printf("[INFO] 클라이언트: %s:%d\n", stats.client_ip, stats.client_port);

    audit_log("SESSION_START", stats.client_ip, stats.client_port,
              "New client connection");

    /* Q-TLS 연결 생성 */
    conn = qtls_new(ctx);
    if (!conn) {
        fprintf(stderr, "[ERROR] qtls_new() 실패\n");
        audit_log("SESSION_ERROR", stats.client_ip, stats.client_port,
                  "Failed to create Q-TLS connection");
        goto cleanup;
    }

    ret = qtls_set_fd(conn, client_fd);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] qtls_set_fd() 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    /* Q-TLS 핸드셰이크 */
    printf("[INFO] Q-TLS 핸드셰이크 시작...\n");
    ret = qtls_accept(conn);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 핸드셰이크 실패: %s\n",
                qtls_get_error_string(ret));
        audit_log("HANDSHAKE_FAILED", stats.client_ip, stats.client_port,
                  qtls_get_error_string(ret));
        goto cleanup;
    }

    printf("[SUCCESS] 핸드셰이크 완료\n");

    /* 협상된 암호 스위트 */
    const char *cipher = qtls_get_cipher(conn);
    if (cipher) {
        strncpy(stats.cipher, cipher, sizeof(stats.cipher) - 1);
        printf("[INFO] 암호 스위트: %s\n", cipher);
    }

    /* 클라이언트 인증서 검증 */
    ret = qtls_verify_peer_certificate(conn);
    if (ret == 1) {
        printf("[SUCCESS] 클라이언트 인증서 검증 완료\n");
        stats.authenticated = 1;

        QTLS_CERTIFICATE *cert = qtls_get_peer_certificate(conn);
        if (cert) {
            printf("[INFO] 클라이언트 인증서 크기: %zu 바이트\n", cert->length);
            audit_log("CLIENT_AUTHENTICATED", stats.client_ip,
                      stats.client_port, "Client certificate verified");
            qtls_certificate_free(cert);
        }
    } else {
        fprintf(stderr, "[ERROR] 클라이언트 인증 실패\n");
        audit_log("AUTH_FAILED", stats.client_ip, stats.client_port,
                  "Client certificate verification failed");
        goto cleanup;
    }

    /* 데이터 수신 및 처리 */
    printf("[INFO] 인증된 클라이언트로부터 데이터 수신 중...\n");

    while (server_running) {
        memset(buffer, 0, sizeof(buffer));
        ret = qtls_read(conn, buffer, sizeof(buffer) - 1);

        if (ret > 0) {
            buffer[ret] = '\0';
            stats.bytes_received += ret;
            total_bytes_received += ret;

            printf("[RECV] %d 바이트: %s\n", ret, buffer);

            /* 에코 응답 */
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response),
                     "QSIGN 서버 응답 [세션 #%lu]: 메시지 수신 완료 (%d 바이트)",
                     stats.session_id, ret);

            ret = qtls_write(conn, response, strlen(response));
            if (ret > 0) {
                stats.bytes_sent += ret;
                total_bytes_sent += ret;
                printf("[SENT] %d 바이트\n", ret);
            }

            /* "quit" 명령 시 종료 */
            if (strstr(buffer, "quit")) {
                printf("[INFO] 클라이언트 종료 요청\n");
                break;
            }
        } else if (ret == 0) {
            printf("[INFO] 클라이언트 연결 종료\n");
            break;
        } else {
            fprintf(stderr, "[ERROR] qtls_read() 실패: %s\n",
                    qtls_get_error_string(ret));
            break;
        }
    }

    qtls_shutdown(conn);

cleanup:
    if (conn) {
        qtls_free(conn);
    }
    close(client_fd);

    stats.end_time = time(NULL);

    /* 세션 통계 출력 */
    printf("\n========== 세션 #%lu 종료 ==========\n", stats.session_id);
    printf("클라이언트: %s:%d\n", stats.client_ip, stats.client_port);
    printf("세션 시간: %ld 초\n", stats.end_time - stats.start_time);
    printf("수신: %zu 바이트, 전송: %zu 바이트\n",
           stats.bytes_received, stats.bytes_sent);
    printf("암호 스위트: %s\n", stats.cipher);
    printf("인증 여부: %s\n", stats.authenticated ? "예" : "아니오");
    printf("====================================\n\n");

    audit_log("SESSION_END", stats.client_ip, stats.client_port,
              stats.authenticated ? "Session completed successfully" :
              "Session ended without authentication");
}

/*
 * 메인 함수
 */
int main(int argc, char *argv[]) {
    QTLS_CTX *ctx = NULL;
    int server_fd = -1;
    int port = SERVER_PORT;
    int use_hsm = 0;
    const char *hsm_pin = NULL;
    const char *server_key = "certs/server.key";
    int ret;

    printf("=======================================================\n");
    printf("  Q-TLS QSIGN Integration Server\n");
    printf("  QSIGN PKI 및 Luna HSM 통합 서버\n");
    printf("=======================================================\n");
    printf("Q-TLS 버전: %s\n", qtls_version());
    printf("빌드 날짜: %s %s\n", __DATE__, __TIME__);
    printf("\n");

    /* 명령행 인자 처리 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hsm") == 0) {
            use_hsm = 1;
        } else if (strcmp(argv[i], "--hsm-pin") == 0 && i + 1 < argc) {
            hsm_pin = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            server_key = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("사용법: %s [옵션]\n", argv[0]);
            printf("옵션:\n");
            printf("  --hsm              Luna HSM 사용\n");
            printf("  --hsm-pin <PIN>    HSM PIN\n");
            printf("  --port <PORT>      서버 포트 (기본: 8443)\n");
            printf("  --key <PATH>       서버 개인키 경로 (HSM 미사용 시)\n");
            printf("  --help             이 도움말 표시\n");
            return 0;
        }
    }

    /* 시그널 핸들러 등록 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);  /* Broken pipe 무시 */

    /* HSM 초기화 (선택적) */
    if (use_hsm) {
        if (!hsm_pin) {
            fprintf(stderr, "[ERROR] HSM PIN이 필요합니다 (--hsm-pin)\n");
            return 1;
        }

        ret = initialize_hsm(hsm_pin);
        if (ret != QTLS_SUCCESS) {
            return 1;
        }
    } else {
        printf("[INFO] 테스트 모드: 파일 기반 키 사용\n");
    }

    /* Q-TLS 컨텍스트 생성 */
    printf("\n[INFO] Q-TLS 서버 컨텍스트 초기화 중...\n");
    ctx = qtls_ctx_new(QTLS_SERVER_MODE);
    if (!ctx) {
        fprintf(stderr, "[ERROR] qtls_ctx_new() 실패\n");
        goto cleanup;
    }

    /* QSIGN PKI 설정 */
    ret = setup_qsign_pki(ctx, use_hsm, server_key);
    if (ret != QTLS_SUCCESS) {
        goto cleanup;
    }

    /* 서버 소켓 생성 */
    server_fd = create_server_socket(port);
    if (server_fd < 0) {
        goto cleanup;
    }

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║  QSIGN Q-TLS 서버 시작                              ║\n");
    printf("╠═══════════════════════════════════════════════════════╣\n");
    printf("║  포트: %-45d  ║\n", port);
    printf("║  HSM: %-46s ║\n", use_hsm ? "활성화 (Luna HSM)" : "비활성화");
    printf("║  인증 모드: %-39s  ║\n", "상호 TLS (mTLS)");
    printf("║  PQC: %-46s ║\n", "Kyber1024 + Dilithium3");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    printf("\n[INFO] 클라이언트 연결 대기 중... (Ctrl+C로 종료)\n\n");

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

        /* 클라이언트 세션 처리 */
        handle_client_session(ctx, client_fd, &client_addr);
    }

    /* 종료 통계 */
    printf("\n========== 서버 종료 통계 ==========\n");
    printf("총 세션 수: %lu\n", session_counter);
    printf("총 수신: %lu 바이트\n", total_bytes_received);
    printf("총 전송: %lu 바이트\n", total_bytes_sent);
    printf("====================================\n");

cleanup:
    if (server_fd >= 0) {
        close(server_fd);
    }
    if (ctx) {
        qtls_ctx_free(ctx);
    }
    if (use_hsm) {
        qtls_hsm_cleanup();
    }

    printf("[INFO] 서버 종료 완료\n");
    return 0;
}
