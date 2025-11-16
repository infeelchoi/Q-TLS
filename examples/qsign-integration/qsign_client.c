/*
 * Q-TLS QSIGN Integration Client Example
 * QSIGN PKI 및 HSM 통합 클라이언트 구현 예제
 *
 * 이 예제는 QSIGN PKI 시스템과 Luna HSM을 통합한
 * 엔터프라이즈급 Q-TLS 클라이언트를 구현하는 방법을 보여줍니다.
 *
 * Copyright 2025 QSIGN Project
 * Licensed under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <qtls/qtls.h>

/* 설정 */
#define BUFFER_SIZE 8192
#define DEFAULT_PORT 8443
#define DEFAULT_HOST "localhost"

/* HSM 설정 */
#define HSM_MODULE_PATH "/usr/lib/libCryptoki2_64.so"
#define HSM_TOKEN_LABEL "qsign-client"
#define HSM_KEY_LABEL "client-key"

/* QSIGN PKI 설정 */
#define QSIGN_CA_CERT "/etc/qsign/ca/root-ca.crt"
#define QSIGN_CLIENT_CERT "/etc/qsign/certs/client.crt"

/*
 * 현재 시각 반환 (밀리초)
 */
long long get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * 호스트명을 IP로 변환
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

    printf("[INFO] TCP 연결 시도 중...\n");
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect() 실패");
        close(sockfd);
        return -1;
    }

    printf("[SUCCESS] TCP 연결 성공\n");
    return sockfd;
}

/*
 * HSM 초기화
 */
int initialize_hsm(const char *pin) {
    int ret;

    printf("[INFO] Luna HSM 초기화 중...\n");
    printf("[INFO] HSM 모듈: %s\n", HSM_MODULE_PATH);

    ret = qtls_hsm_init(HSM_MODULE_PATH);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] HSM 초기화 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }

    printf("[INFO] HSM 로그인 중... (토큰: %s)\n", HSM_TOKEN_LABEL);
    ret = qtls_hsm_login(HSM_TOKEN_LABEL, pin);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] HSM 로그인 실패: %s\n",
                qtls_get_error_string(ret));
        qtls_hsm_cleanup();
        return ret;
    }

    printf("[SUCCESS] Luna HSM 초기화 완료\n");
    return QTLS_SUCCESS;
}

/*
 * QSIGN PKI 컨텍스트 설정
 */
int setup_qsign_client(QTLS_CTX *ctx, int use_hsm, const char *client_key_path) {
    int ret;

    /* 하이브리드 모드 활성화 */
    ret = qtls_ctx_set_options(ctx, QTLS_OP_HYBRID_MODE);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 하이브리드 모드 활성화 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }
    printf("[INFO] 하이브리드 PQC 모드 활성화\n");

    /* 클라이언트 인증서 로드 */
    printf("[INFO] 클라이언트 인증서 로드: %s\n", QSIGN_CLIENT_CERT);
    ret = qtls_ctx_use_certificate_file(ctx, QSIGN_CLIENT_CERT, QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 클라이언트 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }

    /* 클라이언트 개인키 로드 */
    if (use_hsm) {
        char hsm_uri[256];
        snprintf(hsm_uri, sizeof(hsm_uri),
                 "pkcs11:token=%s;object=%s",
                 HSM_TOKEN_LABEL, HSM_KEY_LABEL);

        printf("[INFO] HSM에서 개인키 로드: %s\n", hsm_uri);
        ret = qtls_ctx_use_hsm_key(ctx, hsm_uri);
        if (ret != QTLS_SUCCESS) {
            fprintf(stderr, "[ERROR] HSM 개인키 로드 실패: %s\n",
                    qtls_get_error_string(ret));
            return ret;
        }
        printf("[SUCCESS] HSM 개인키 로드 완료\n");
    } else {
        printf("[WARN] 파일에서 개인키 로드 (테스트 모드)\n");
        printf("[INFO] 개인키: %s\n", client_key_path);
        ret = qtls_ctx_use_private_key_file(ctx, client_key_path, QTLS_FILETYPE_PEM);
        if (ret != QTLS_SUCCESS) {
            fprintf(stderr, "[ERROR] 개인키 로드 실패: %s\n",
                    qtls_get_error_string(ret));
            return ret;
        }
    }

    /* CA 인증서 로드 */
    printf("[INFO] QSIGN CA 인증서 로드: %s\n", QSIGN_CA_CERT);
    ret = qtls_ctx_load_verify_locations(ctx, QSIGN_CA_CERT, NULL);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] CA 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }

    /* 서버 인증서 검증 활성화 */
    ret = qtls_ctx_set_verify_mode(ctx, QTLS_VERIFY_PEER, NULL);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 검증 모드 설정 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }
    printf("[INFO] 서버 인증서 검증 활성화\n");

    /* PQC 알고리즘 설정 */
    uint16_t kems[] = {QTLS_KEM_KYBER1024, QTLS_KEM_ECDHE_P384};
    uint16_t sigs[] = {QTLS_SIG_DILITHIUM3, QTLS_SIG_ECDSA_P384};
    ret = qtls_ctx_set_pqc_algorithms(ctx, kems, 2, sigs, 2);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] PQC 알고리즘 설정 실패: %s\n",
                qtls_get_error_string(ret));
        return ret;
    }
    printf("[INFO] PQC 알고리즘: Kyber1024+ECDHE, Dilithium3+ECDSA\n");

    return QTLS_SUCCESS;
}

/*
 * Q-TLS 통신 수행
 */
int perform_qtls_communication(const char *host, int port, int use_hsm,
                               const char *client_key) {
    QTLS_CTX *ctx = NULL;
    QTLS_CONNECTION *conn = NULL;
    int sockfd = -1;
    char buffer[BUFFER_SIZE];
    int ret;
    int retval = -1;
    long long handshake_start, handshake_end;

    printf("\n[INFO] Q-TLS 클라이언트 초기화 중...\n");

    /* Q-TLS 컨텍스트 생성 */
    ctx = qtls_ctx_new(QTLS_CLIENT_MODE);
    if (!ctx) {
        fprintf(stderr, "[ERROR] qtls_ctx_new() 실패\n");
        return -1;
    }

    /* QSIGN PKI 설정 */
    ret = setup_qsign_client(ctx, use_hsm, client_key);
    if (ret != QTLS_SUCCESS) {
        goto cleanup;
    }

    /* 서버에 TCP 연결 */
    sockfd = connect_to_server(host, port);
    if (sockfd < 0) {
        goto cleanup;
    }

    /* Q-TLS 연결 생성 */
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

    /* Q-TLS 핸드셰이크 (성능 측정) */
    printf("\n[INFO] Q-TLS 상호 인증 핸드셰이크 시작...\n");
    handshake_start = get_time_ms();

    ret = qtls_connect(conn);

    handshake_end = get_time_ms();

    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 핸드셰이크 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    printf("[SUCCESS] 핸드셰이크 완료! (소요 시간: %lld ms)\n",
           handshake_end - handshake_start);

    /* 협상 정보 출력 */
    printf("\n========== 연결 정보 ==========\n");

    const char *cipher = qtls_get_cipher(conn);
    printf("암호 스위트: %s\n", cipher ? cipher : "Unknown");

    int version = qtls_get_version(conn);
    printf("프로토콜 버전: 0x%04X\n", version);

    /* 서버 인증서 검증 */
    ret = qtls_verify_peer_certificate(conn);
    if (ret == 1) {
        printf("서버 인증: 검증됨\n");

        QTLS_CERTIFICATE *cert = qtls_get_peer_certificate(conn);
        if (cert) {
            printf("서버 인증서 크기: %zu 바이트\n", cert->length);
            qtls_certificate_free(cert);
        }
    } else {
        printf("서버 인증: 실패\n");
    }

    printf("================================\n\n");

    /* 대화형 메시지 전송 */
    printf("[INFO] 메시지를 입력하세요 (종료: quit)\n\n");

    while (1) {
        printf("메시지> ");
        fflush(stdout);

        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break;
        }

        /* 개행 제거 */
        buffer[strcspn(buffer, "\n")] = 0;

        if (strlen(buffer) == 0) {
            continue;
        }

        /* "quit" 명령 확인 */
        if (strcmp(buffer, "quit") == 0) {
            printf("[INFO] 연결 종료 중...\n");
            qtls_write(conn, "quit", 4);
            break;
        }

        /* 메시지 전송 */
        ret = qtls_write(conn, buffer, strlen(buffer));
        if (ret <= 0) {
            fprintf(stderr, "[ERROR] 전송 실패: %s\n",
                    qtls_get_error_string(ret));
            break;
        }

        printf("[SENT] %d 바이트\n", ret);

        /* 응답 수신 */
        memset(buffer, 0, sizeof(buffer));
        ret = qtls_read(conn, buffer, sizeof(buffer) - 1);

        if (ret > 0) {
            buffer[ret] = '\0';
            printf("[RECV] %s\n\n", buffer);
        } else if (ret == 0) {
            printf("[INFO] 서버가 연결을 종료했습니다.\n");
            break;
        } else {
            fprintf(stderr, "[ERROR] 수신 실패: %s\n",
                    qtls_get_error_string(ret));
            break;
        }
    }

    retval = 0;
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
    int use_hsm = 0;
    const char *hsm_pin = NULL;
    const char *client_key = "certs/client.key";

    printf("=======================================================\n");
    printf("  Q-TLS QSIGN Integration Client\n");
    printf("  QSIGN PKI 및 Luna HSM 통합 클라이언트\n");
    printf("=======================================================\n");
    printf("Q-TLS 버전: %s\n", qtls_version());
    printf("\n");

    /* 명령행 인자 처리 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--hsm") == 0) {
            use_hsm = 1;
        } else if (strcmp(argv[i], "--hsm-pin") == 0 && i + 1 < argc) {
            hsm_pin = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            client_key = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("사용법: %s [옵션]\n", argv[0]);
            printf("옵션:\n");
            printf("  --host <HOST>      서버 호스트 (기본: localhost)\n");
            printf("  --port <PORT>      서버 포트 (기본: 8443)\n");
            printf("  --hsm              Luna HSM 사용\n");
            printf("  --hsm-pin <PIN>    HSM PIN\n");
            printf("  --key <PATH>       클라이언트 개인키 경로\n");
            printf("  --help             이 도움말 표시\n");
            return 0;
        }
    }

    /* HSM 초기화 (선택적) */
    if (use_hsm) {
        if (!hsm_pin) {
            fprintf(stderr, "[ERROR] HSM PIN이 필요합니다 (--hsm-pin)\n");
            return 1;
        }

        if (initialize_hsm(hsm_pin) != QTLS_SUCCESS) {
            return 1;
        }
    } else {
        printf("[INFO] 테스트 모드: 파일 기반 키 사용\n");
    }

    printf("\n연결 설정:\n");
    printf("  서버: %s:%d\n", host, port);
    printf("  HSM: %s\n", use_hsm ? "활성화" : "비활성화");
    printf("  인증 모드: 상호 TLS\n");
    printf("\n");

    /* Q-TLS 통신 수행 */
    int result = perform_qtls_communication(host, port, use_hsm, client_key);

    if (use_hsm) {
        qtls_hsm_cleanup();
    }

    if (result == 0) {
        printf("\n[SUCCESS] 통신 완료\n");
        return 0;
    } else {
        printf("\n[FAILED] 통신 실패\n");
        return 1;
    }
}
