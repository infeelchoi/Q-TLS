/*
 * Q-TLS 인증서 생성 도구
 * 양자 내성 알고리즘(Dilithium)을 사용한 인증서 생성 유틸리티
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define DEFAULT_DAYS 365
#define DEFAULT_KEY_SIZE 2048

typedef enum {
    CERT_TYPE_CA,
    CERT_TYPE_SERVER,
    CERT_TYPE_CLIENT
} CertType;

typedef struct {
    CertType type;
    char *algorithm;      // "dilithium3", "dilithium5", "rsa", "ec"
    char *subject;        // Distinguished Name
    char *ca_cert;        // CA 인증서 경로 (CA가 아닌 경우)
    char *ca_key;         // CA 키 경로 (CA가 아닌 경우)
    char *output_cert;    // 출력 인증서 경로
    char *output_key;     // 출력 키 경로
    int days;             // 유효 기간 (일)
    char **san_list;      // Subject Alternative Names
    int san_count;
} CertGenConfig;

/* 에러 처리 */
void print_openssl_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

/* 개인키 생성 */
EVP_PKEY* generate_key(const char *algorithm) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    printf("키 생성 중 (알고리즘: %s)...\n", algorithm);

    // Dilithium 알고리즘 시도
    if (strcmp(algorithm, "dilithium3") == 0 ||
        strcmp(algorithm, "dilithium5") == 0) {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
        if (ctx == NULL) {
            fprintf(stderr, "경고: %s 알고리즘을 사용할 수 없습니다. RSA로 대체합니다.\n", algorithm);
            goto use_rsa;
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            print_openssl_error("키 생성 초기화 실패");
            EVP_PKEY_CTX_free(ctx);
            goto use_rsa;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            print_openssl_error("키 생성 실패");
            EVP_PKEY_CTX_free(ctx);
            goto use_rsa;
        }

        EVP_PKEY_CTX_free(ctx);
        return pkey;
    }

use_rsa:
    // RSA 키 생성 (fallback)
    if (strcmp(algorithm, "rsa") == 0 || pkey == NULL) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (ctx == NULL) {
            print_openssl_error("RSA 컨텍스트 생성 실패");
            return NULL;
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, DEFAULT_KEY_SIZE) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            print_openssl_error("RSA 키 생성 실패");
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }

        EVP_PKEY_CTX_free(ctx);
    }

    return pkey;
}

/* X509 이름 설정 */
int set_subject_name(X509 *cert, const char *subject_str) {
    X509_NAME *name = X509_NAME_new();
    if (name == NULL) {
        return 0;
    }

    // 간단한 파싱 (형식: /C=KR/ST=Seoul/O=Example/CN=example.com)
    char *subject_copy = strdup(subject_str);
    char *token = strtok(subject_copy, "/");

    while (token != NULL) {
        char *equals = strchr(token, '=');
        if (equals != NULL) {
            *equals = '\0';
            char *key = token;
            char *value = equals + 1;

            X509_NAME_add_entry_by_txt(name, key, MBSTRING_ASC,
                                      (unsigned char *)value, -1, -1, 0);
        }
        token = strtok(NULL, "/");
    }

    free(subject_copy);
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);

    return 1;
}

/* SAN (Subject Alternative Names) 추가 */
int add_san_extension(X509 *cert, char **san_list, int san_count) {
    if (san_count == 0) {
        return 1;
    }

    // SAN 문자열 생성
    char san_str[4096] = {0};
    for (int i = 0; i < san_count; i++) {
        if (i > 0) {
            strcat(san_str, ",");
        }
        strcat(san_str, "DNS:");
        strcat(san_str, san_list[i]);
    }

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_str);
    if (ext == NULL) {
        print_openssl_error("SAN 확장 생성 실패");
        return 0;
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    return 1;
}

/* CA 인증서 생성 */
X509* create_ca_certificate(EVP_PKEY *pkey, const char *subject, int days) {
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }

    // 버전 설정 (v3 = 2)
    X509_set_version(cert, 2);

    // 시리얼 번호 설정
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // 유효 기간 설정
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * days);

    // Subject와 Issuer 설정 (CA는 자체 서명)
    set_subject_name(cert, subject);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));

    // 공개키 설정
    X509_set_pubkey(cert, pkey);

    // CA 확장 추가
    X509_EXTENSION *ext;
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,keyCertSign,cRLSign");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // 자체 서명
    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        print_openssl_error("CA 인증서 서명 실패");
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* 서버/클라이언트 인증서 생성 */
X509* create_end_entity_certificate(EVP_PKEY *pkey, const char *subject,
                                    X509 *ca_cert, EVP_PKEY *ca_key,
                                    int days, CertType type,
                                    char **san_list, int san_count) {
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }

    // 버전 설정
    X509_set_version(cert, 2);

    // 시리얼 번호 설정 (임의)
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)rand());

    // 유효 기간 설정
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * days);

    // Subject 설정
    set_subject_name(cert, subject);

    // Issuer 설정 (CA)
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // 공개키 설정
    X509_set_pubkey(cert, pkey);

    // 확장 추가
    X509_EXTENSION *ext;
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    if (type == CERT_TYPE_SERVER) {
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
                                 "critical,digitalSignature,keyEncipherment");
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "serverAuth");
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        // SAN 추가
        add_san_extension(cert, san_list, san_count);
    } else if (type == CERT_TYPE_CLIENT) {
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
                                 "critical,digitalSignature");
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "clientAuth");
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // CA 서명
    if (X509_sign(cert, ca_key, EVP_sha256()) == 0) {
        print_openssl_error("인증서 서명 실패");
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* 사용법 출력 */
void print_usage(const char *prog) {
    printf("사용법: %s [옵션]\n\n", prog);
    printf("옵션:\n");
    printf("  -t TYPE         인증서 타입 (ca, server, client)\n");
    printf("  -a ALGORITHM    알고리즘 (dilithium3, dilithium5, rsa) [기본: dilithium3]\n");
    printf("  -s SUBJECT      Subject DN (예: /C=KR/O=Example/CN=example.com)\n");
    printf("  -d DAYS         유효 기간 (일) [기본: 365]\n");
    printf("  -o CERT_FILE    출력 인증서 파일\n");
    printf("  -k KEY_FILE     출력 키 파일\n");
    printf("  -c CA_CERT      CA 인증서 (서버/클라이언트 인증서용)\n");
    printf("  -K CA_KEY       CA 키 (서버/클라이언트 인증서용)\n");
    printf("  -n SAN          Subject Alternative Name (서버 인증서용, 반복 가능)\n");
    printf("  -h              도움말 표시\n\n");
    printf("예제:\n");
    printf("  # CA 인증서 생성\n");
    printf("  %s -t ca -s '/C=KR/O=MyCA/CN=My CA' -o ca.pem -k ca-key.pem\n\n", prog);
    printf("  # 서버 인증서 생성\n");
    printf("  %s -t server -s '/C=KR/O=MyOrg/CN=server.example.com' \\\n", prog);
    printf("       -c ca.pem -K ca-key.pem -o server.pem -k server-key.pem \\\n");
    printf("       -n server.example.com -n www.example.com\n");
}

int main(int argc, char **argv) {
    CertGenConfig config = {0};
    config.type = CERT_TYPE_CA;
    config.algorithm = "dilithium3";
    config.days = DEFAULT_DAYS;
    config.san_list = malloc(sizeof(char*) * 10);
    config.san_count = 0;

    int opt;
    while ((opt = getopt(argc, argv, "t:a:s:d:o:k:c:K:n:h")) != -1) {
        switch (opt) {
            case 't':
                if (strcmp(optarg, "ca") == 0) config.type = CERT_TYPE_CA;
                else if (strcmp(optarg, "server") == 0) config.type = CERT_TYPE_SERVER;
                else if (strcmp(optarg, "client") == 0) config.type = CERT_TYPE_CLIENT;
                break;
            case 'a':
                config.algorithm = optarg;
                break;
            case 's':
                config.subject = optarg;
                break;
            case 'd':
                config.days = atoi(optarg);
                break;
            case 'o':
                config.output_cert = optarg;
                break;
            case 'k':
                config.output_key = optarg;
                break;
            case 'c':
                config.ca_cert = optarg;
                break;
            case 'K':
                config.ca_key = optarg;
                break;
            case 'n':
                config.san_list[config.san_count++] = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // 필수 인자 확인
    if (config.subject == NULL || config.output_cert == NULL || config.output_key == NULL) {
        fprintf(stderr, "오류: Subject(-s), 출력 인증서(-o), 출력 키(-k)는 필수입니다.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (config.type != CERT_TYPE_CA && (config.ca_cert == NULL || config.ca_key == NULL)) {
        fprintf(stderr, "오류: 서버/클라이언트 인증서는 CA 인증서(-c)와 CA 키(-K)가 필요합니다.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // OpenSSL 초기화
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 키 생성
    EVP_PKEY *pkey = generate_key(config.algorithm);
    if (pkey == NULL) {
        fprintf(stderr, "키 생성 실패\n");
        return 1;
    }

    X509 *cert = NULL;

    if (config.type == CERT_TYPE_CA) {
        // CA 인증서 생성
        printf("CA 인증서 생성 중...\n");
        cert = create_ca_certificate(pkey, config.subject, config.days);
    } else {
        // CA 인증서와 키 로드
        FILE *ca_cert_file = fopen(config.ca_cert, "r");
        X509 *ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
        fclose(ca_cert_file);

        FILE *ca_key_file = fopen(config.ca_key, "r");
        EVP_PKEY *ca_key = PEM_read_PrivateKey(ca_key_file, NULL, NULL, NULL);
        fclose(ca_key_file);

        if (ca_cert == NULL || ca_key == NULL) {
            fprintf(stderr, "CA 인증서 또는 키 로드 실패\n");
            EVP_PKEY_free(pkey);
            return 1;
        }

        // 서버/클라이언트 인증서 생성
        printf("%s 인증서 생성 중...\n",
               config.type == CERT_TYPE_SERVER ? "서버" : "클라이언트");
        cert = create_end_entity_certificate(pkey, config.subject, ca_cert, ca_key,
                                            config.days, config.type,
                                            config.san_list, config.san_count);

        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
    }

    if (cert == NULL) {
        fprintf(stderr, "인증서 생성 실패\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    // 인증서 저장
    FILE *cert_file = fopen(config.output_cert, "w");
    PEM_write_X509(cert_file, cert);
    fclose(cert_file);

    // 키 저장
    FILE *key_file = fopen(config.output_key, "w");
    PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_file);

    printf("성공!\n");
    printf("  인증서: %s\n", config.output_cert);
    printf("  키: %s\n", config.output_key);

    X509_free(cert);
    EVP_PKEY_free(pkey);
    free(config.san_list);

    return 0;
}
