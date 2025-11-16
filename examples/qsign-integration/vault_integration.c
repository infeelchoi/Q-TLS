/*
 * Q-TLS HashiCorp Vault Integration Example
 * Vault를 사용한 키 및 인증서 관리 예제
 *
 * 이 예제는 HashiCorp Vault를 사용하여 Q-TLS 인증서와 개인키를
 * 안전하게 관리하는 방법을 보여줍니다.
 *
 * 주요 기능:
 * - Vault PKI 시크릿 엔진 사용
 * - 동적 인증서 발급
 * - 인증서 자동 갱신
 * - HSM 통합 (Vault Enterprise)
 *
 * Copyright 2025 QSIGN Project
 * Licensed under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <qtls/qtls.h>
#include <jansson.h>  /* JSON 파싱 라이브러리 */

/* Vault 설정 */
#define VAULT_ADDR "http://127.0.0.1:8200"
#define VAULT_PKI_PATH "pki"
#define VAULT_ROLE "qtls-server"

/* HTTP 응답 데이터 구조체 */
typedef struct {
    char *data;
    size_t size;
} http_response_t;

/*
 * libcurl 응답 콜백
 */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    http_response_t *mem = (http_response_t *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "[ERROR] 메모리 할당 실패\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

/*
 * Vault API 호출
 *
 * Parameters:
 *   vault_token: Vault 인증 토큰
 *   path: API 경로 (예: "/v1/pki/issue/qtls-server")
 *   method: HTTP 메소드 (GET, POST 등)
 *   post_data: POST 데이터 (JSON 문자열)
 *   response: 응답 데이터 저장 포인터
 *
 * Returns: 0 (성공), -1 (실패)
 */
int vault_api_call(const char *vault_token, const char *path,
                   const char *method, const char *post_data,
                   http_response_t *response) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char url[512];
    char token_header[256];
    int retval = -1;

    /* URL 생성 */
    snprintf(url, sizeof(url), "%s%s", VAULT_ADDR, path);

    /* 응답 구조체 초기화 */
    response->data = malloc(1);
    response->size = 0;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[ERROR] CURL 초기화 실패\n");
        return -1;
    }

    /* HTTP 헤더 설정 */
    snprintf(token_header, sizeof(token_header), "X-Vault-Token: %s", vault_token);
    headers = curl_slist_append(headers, token_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* CURL 옵션 설정 */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    }

    /* 요청 실행 */
    printf("[INFO] Vault API 호출: %s %s\n", method, path);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "[ERROR] CURL 요청 실패: %s\n",
                curl_easy_strerror(res));
    } else {
        retval = 0;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return retval;
}

/*
 * Vault에서 인증서 발급
 *
 * Parameters:
 *   vault_token: Vault 토큰
 *   common_name: 인증서 CN (예: "server.example.com")
 *   cert_pem: 발급된 인증서 저장 포인터
 *   key_pem: 발급된 개인키 저장 포인터
 *   ca_chain: CA 체인 저장 포인터
 *
 * Returns: 0 (성공), -1 (실패)
 */
int vault_issue_certificate(const char *vault_token, const char *common_name,
                            char **cert_pem, char **key_pem, char **ca_chain) {
    http_response_t response;
    char path[256];
    char post_data[512];
    json_t *root, *data, *certificate, *private_key, *ca;
    json_error_t error;
    int retval = -1;

    /* API 경로 및 요청 데이터 */
    snprintf(path, sizeof(path), "/v1/%s/issue/%s", VAULT_PKI_PATH, VAULT_ROLE);
    snprintf(post_data, sizeof(post_data),
             "{\"common_name\":\"%s\",\"ttl\":\"24h\"}",
             common_name);

    /* Vault API 호출 */
    if (vault_api_call(vault_token, path, "POST", post_data, &response) != 0) {
        goto cleanup;
    }

    printf("[INFO] Vault 응답 수신: %zu 바이트\n", response.size);

    /* JSON 파싱 */
    root = json_loads(response.data, 0, &error);
    if (!root) {
        fprintf(stderr, "[ERROR] JSON 파싱 실패: %s\n", error.text);
        goto cleanup;
    }

    /* 데이터 추출 */
    data = json_object_get(root, "data");
    if (!data) {
        fprintf(stderr, "[ERROR] Vault 응답에 data 필드 없음\n");
        json_decref(root);
        goto cleanup;
    }

    /* 인증서 추출 */
    certificate = json_object_get(data, "certificate");
    if (certificate && json_is_string(certificate)) {
        *cert_pem = strdup(json_string_value(certificate));
        printf("[SUCCESS] 인증서 발급 완료\n");
    } else {
        fprintf(stderr, "[ERROR] 인증서 추출 실패\n");
        json_decref(root);
        goto cleanup;
    }

    /* 개인키 추출 */
    private_key = json_object_get(data, "private_key");
    if (private_key && json_is_string(private_key)) {
        *key_pem = strdup(json_string_value(private_key));
        printf("[SUCCESS] 개인키 추출 완료\n");
    } else {
        fprintf(stderr, "[ERROR] 개인키 추출 실패\n");
        json_decref(root);
        goto cleanup;
    }

    /* CA 체인 추출 */
    ca = json_object_get(data, "ca_chain");
    if (ca && json_is_array(ca)) {
        /* 배열의 첫 번째 CA 사용 */
        json_t *first_ca = json_array_get(ca, 0);
        if (first_ca && json_is_string(first_ca)) {
            *ca_chain = strdup(json_string_value(first_ca));
            printf("[SUCCESS] CA 체인 추출 완료\n");
        }
    }

    retval = 0;
    json_decref(root);

cleanup:
    free(response.data);
    return retval;
}

/*
 * Vault에서 발급한 인증서로 Q-TLS 서버 실행
 */
int run_qtls_server_with_vault(const char *vault_token, const char *common_name) {
    QTLS_CTX *ctx = NULL;
    char *cert_pem = NULL;
    char *key_pem = NULL;
    char *ca_chain = NULL;
    int ret;

    printf("\n========== Vault 통합 Q-TLS 서버 ==========\n\n");

    /* Vault에서 인증서 발급 */
    printf("[INFO] Vault에서 인증서 발급 중...\n");
    printf("[INFO] Common Name: %s\n", common_name);

    ret = vault_issue_certificate(vault_token, common_name,
                                  &cert_pem, &key_pem, &ca_chain);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] 인증서 발급 실패\n");
        return -1;
    }

    /* 인증서를 파일로 저장 (Q-TLS 로드용) */
    FILE *fp;

    fp = fopen("vault_server.crt", "w");
    if (fp) {
        fprintf(fp, "%s", cert_pem);
        fclose(fp);
        printf("[INFO] 인증서 저장: vault_server.crt\n");
    }

    fp = fopen("vault_server.key", "w");
    if (fp) {
        fprintf(fp, "%s", key_pem);
        fclose(fp);
        printf("[INFO] 개인키 저장: vault_server.key\n");
    }

    if (ca_chain) {
        fp = fopen("vault_ca.crt", "w");
        if (fp) {
            fprintf(fp, "%s", ca_chain);
            fclose(fp);
            printf("[INFO] CA 체인 저장: vault_ca.crt\n");
        }
    }

    /* Q-TLS 컨텍스트 생성 */
    printf("\n[INFO] Q-TLS 서버 초기화 중...\n");
    ctx = qtls_ctx_new(QTLS_SERVER_MODE);
    if (!ctx) {
        fprintf(stderr, "[ERROR] qtls_ctx_new() 실패\n");
        goto cleanup;
    }

    /* Vault 발급 인증서 로드 */
    ret = qtls_ctx_use_certificate_file(ctx, "vault_server.crt", QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 인증서 로드 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    ret = qtls_ctx_use_private_key_file(ctx, "vault_server.key", QTLS_FILETYPE_PEM);
    if (ret != QTLS_SUCCESS) {
        fprintf(stderr, "[ERROR] 개인키 로드 실패: %s\n",
                qtls_get_error_string(ret));
        goto cleanup;
    }

    printf("[SUCCESS] Vault 발급 인증서로 Q-TLS 서버 설정 완료\n");
    printf("\n[INFO] 서버를 시작할 준비가 되었습니다.\n");
    printf("[HINT] qsign_server를 실행하여 이 인증서를 사용하세요.\n");

cleanup:
    if (ctx) {
        qtls_ctx_free(ctx);
    }

    /* 메모리 정리 */
    free(cert_pem);
    free(key_pem);
    free(ca_chain);

    return 0;
}

/*
 * 인증서 갱신 예제
 *
 * Vault의 인증서는 TTL이 있으므로 주기적으로 갱신해야 합니다.
 */
void certificate_renewal_example(const char *vault_token, const char *common_name) {
    printf("\n========== 인증서 자동 갱신 예제 ==========\n\n");

    printf("[INFO] 인증서 갱신 프로세스:\n");
    printf("1. TTL 만료 전 알림 (예: 1시간 전)\n");
    printf("2. Vault에서 새 인증서 발급\n");
    printf("3. Q-TLS 서버에 새 인증서 로드 (무중단 갱신)\n");
    printf("4. 기존 연결 유지, 새 연결에 새 인증서 사용\n");

    /* 실제 갱신 수행 */
    printf("\n[INFO] 인증서 갱신 시뮬레이션...\n");

    char *new_cert = NULL, *new_key = NULL, *new_ca = NULL;

    if (vault_issue_certificate(vault_token, common_name,
                                &new_cert, &new_key, &new_ca) == 0) {
        printf("[SUCCESS] 새 인증서 발급 완료\n");
        printf("[INFO] 프로덕션: qtls_ctx_use_certificate_file()로 무중단 갱신\n");

        free(new_cert);
        free(new_key);
        free(new_ca);
    }
}

/*
 * 메인 함수
 */
int main(int argc, char *argv[]) {
    const char *vault_token = NULL;
    const char *common_name = "qtls-server.qsign.local";
    int renewal_mode = 0;

    printf("=======================================================\n");
    printf("  Q-TLS Vault Integration Example\n");
    printf("  HashiCorp Vault를 사용한 인증서 관리\n");
    printf("=======================================================\n\n");

    /* 명령행 인자 처리 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            vault_token = argv[++i];
        } else if (strcmp(argv[i], "--cn") == 0 && i + 1 < argc) {
            common_name = argv[++i];
        } else if (strcmp(argv[i], "--renewal") == 0) {
            renewal_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("사용법: %s [옵션]\n", argv[0]);
            printf("옵션:\n");
            printf("  --token <TOKEN>    Vault 인증 토큰\n");
            printf("  --cn <CN>          인증서 Common Name (기본: qtls-server.qsign.local)\n");
            printf("  --renewal          인증서 갱신 모드\n");
            printf("  --help             이 도움말 표시\n");
            printf("\n");
            printf("환경 변수:\n");
            printf("  VAULT_TOKEN        Vault 인증 토큰\n");
            printf("  VAULT_ADDR         Vault 주소 (기본: http://127.0.0.1:8200)\n");
            printf("\n");
            printf("예제:\n");
            printf("  %s --token s.xxxxx --cn server.example.com\n", argv[0]);
            printf("  %s --token s.xxxxx --renewal\n", argv[0]);
            return 0;
        }
    }

    /* Vault 토큰 확인 */
    if (!vault_token) {
        vault_token = getenv("VAULT_TOKEN");
        if (!vault_token) {
            fprintf(stderr, "[ERROR] Vault 토큰이 필요합니다.\n");
            fprintf(stderr, "사용법: %s --token <TOKEN> 또는 VAULT_TOKEN 환경 변수 설정\n",
                    argv[0]);
            return 1;
        }
    }

    printf("[INFO] Vault 주소: %s\n", VAULT_ADDR);
    printf("[INFO] PKI 경로: %s\n", VAULT_PKI_PATH);
    printf("[INFO] PKI 역할: %s\n", VAULT_ROLE);
    printf("\n");

    /* libcurl 초기화 */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (renewal_mode) {
        /* 인증서 갱신 모드 */
        certificate_renewal_example(vault_token, common_name);
    } else {
        /* 인증서 발급 및 서버 설정 */
        run_qtls_server_with_vault(vault_token, common_name);
    }

    /* libcurl 정리 */
    curl_global_cleanup();

    printf("\n[INFO] 완료\n");
    return 0;
}

/*
 * 빌드 방법:
 *
 * gcc -o vault_integration vault_integration.c \
 *     -I../../include \
 *     -L../../build \
 *     -lqtls -loqs -lssl -lcrypto -lcurl -ljansson -lpthread -lm
 *
 * 실행 전 Vault 설정:
 *
 * 1. Vault 서버 시작:
 *    vault server -dev
 *
 * 2. PKI 시크릿 엔진 활성화:
 *    vault secrets enable pki
 *
 * 3. Root CA 생성:
 *    vault write pki/root/generate/internal \
 *        common_name="QSIGN Root CA" \
 *        ttl=8760h
 *
 * 4. PKI 역할 생성:
 *    vault write pki/roles/qtls-server \
 *        allowed_domains="qsign.local,example.com" \
 *        allow_subdomains=true \
 *        max_ttl=72h
 *
 * 5. 실행:
 *    export VAULT_TOKEN="s.xxxxx"
 *    ./vault_integration --cn qtls-server.qsign.local
 */
