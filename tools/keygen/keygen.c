/*
 * Q-TLS 키 생성 도구
 * 양자 내성 암호화 키 쌍 생성 (Kyber, Dilithium)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <oqs/oqs.h>

#define MAX_PATH 256

typedef enum {
    KEY_TYPE_KEM,    // Key Encapsulation Mechanism (Kyber)
    KEY_TYPE_SIG     // Digital Signature (Dilithium)
} KeyType;

typedef struct {
    KeyType type;
    char *algorithm;       // "Kyber512", "Kyber768", "Kyber1024", "Dilithium2", etc.
    char *output_public;   // 공개키 출력 경로
    char *output_secret;   // 비밀키 출력 경로
    int verbose;           // 상세 출력
} KeyGenConfig;

/* 사용 가능한 알고리즘 출력 */
void print_supported_algorithms() {
    printf("\n지원되는 KEM 알고리즘:\n");
    for (size_t i = 0; i < OQS_KEM_alg_count(); i++) {
        const char *alg = OQS_KEM_alg_identifier(i);
        if (OQS_KEM_alg_is_enabled(alg)) {
            OQS_KEM *kem = OQS_KEM_new(alg);
            if (kem != NULL) {
                printf("  - %s (공개키: %zu bytes, 비밀키: %zu bytes)\n",
                       alg, kem->length_public_key, kem->length_secret_key);
                OQS_KEM_free(kem);
            }
        }
    }

    printf("\n지원되는 서명 알고리즘:\n");
    for (size_t i = 0; i < OQS_SIG_alg_count(); i++) {
        const char *alg = OQS_SIG_alg_identifier(i);
        if (OQS_SIG_alg_is_enabled(alg)) {
            OQS_SIG *sig = OQS_SIG_new(alg);
            if (sig != NULL) {
                printf("  - %s (공개키: %zu bytes, 비밀키: %zu bytes)\n",
                       alg, sig->length_public_key, sig->length_secret_key);
                OQS_SIG_free(sig);
            }
        }
    }
}

/* KEM 키 쌍 생성 */
int generate_kem_keypair(const char *algorithm, const char *pub_file, const char *sec_file, int verbose) {
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    int ret = -1;

    if (verbose) {
        printf("KEM 키 쌍 생성 중...\n");
        printf("  알고리즘: %s\n", algorithm);
    }

    // KEM 객체 생성
    kem = OQS_KEM_new(algorithm);
    if (kem == NULL) {
        fprintf(stderr, "오류: 알고리즘 '%s'을(를) 지원하지 않습니다.\n", algorithm);
        fprintf(stderr, "지원되는 알고리즘을 보려면 --list 옵션을 사용하세요.\n");
        goto cleanup;
    }

    // 키 메모리 할당
    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);

    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "메모리 할당 실패\n");
        goto cleanup;
    }

    // 키 쌍 생성
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "키 쌍 생성 실패\n");
        goto cleanup;
    }

    if (verbose) {
        printf("  공개키 크기: %zu bytes\n", kem->length_public_key);
        printf("  비밀키 크기: %zu bytes\n", kem->length_secret_key);
    }

    // 공개키 저장
    FILE *pub_fp = fopen(pub_file, "wb");
    if (pub_fp == NULL) {
        fprintf(stderr, "공개키 파일 생성 실패: %s\n", pub_file);
        goto cleanup;
    }
    fwrite(public_key, 1, kem->length_public_key, pub_fp);
    fclose(pub_fp);

    // 비밀키 저장
    FILE *sec_fp = fopen(sec_file, "wb");
    if (sec_fp == NULL) {
        fprintf(stderr, "비밀키 파일 생성 실패: %s\n", sec_file);
        goto cleanup;
    }
    fwrite(secret_key, 1, kem->length_secret_key, sec_fp);
    fclose(sec_fp);

    printf("키 생성 완료!\n");
    printf("  공개키: %s (%zu bytes)\n", pub_file, kem->length_public_key);
    printf("  비밀키: %s (%zu bytes)\n", sec_file, kem->length_secret_key);

    ret = 0;

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (public_key) {
        OQS_MEM_secure_free(public_key, kem ? kem->length_public_key : 0);
    }
    if (secret_key) {
        OQS_MEM_secure_free(secret_key, kem ? kem->length_secret_key : 0);
    }

    return ret;
}

/* 서명 키 쌍 생성 */
int generate_sig_keypair(const char *algorithm, const char *pub_file, const char *sec_file, int verbose) {
    OQS_SIG *sig = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    int ret = -1;

    if (verbose) {
        printf("서명 키 쌍 생성 중...\n");
        printf("  알고리즘: %s\n", algorithm);
    }

    // SIG 객체 생성
    sig = OQS_SIG_new(algorithm);
    if (sig == NULL) {
        fprintf(stderr, "오류: 알고리즘 '%s'을(를) 지원하지 않습니다.\n", algorithm);
        fprintf(stderr, "지원되는 알고리즘을 보려면 --list 옵션을 사용하세요.\n");
        goto cleanup;
    }

    // 키 메모리 할당
    public_key = malloc(sig->length_public_key);
    secret_key = malloc(sig->length_secret_key);

    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "메모리 할당 실패\n");
        goto cleanup;
    }

    // 키 쌍 생성
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "키 쌍 생성 실패\n");
        goto cleanup;
    }

    if (verbose) {
        printf("  공개키 크기: %zu bytes\n", sig->length_public_key);
        printf("  비밀키 크기: %zu bytes\n", sig->length_secret_key);
    }

    // 공개키 저장
    FILE *pub_fp = fopen(pub_file, "wb");
    if (pub_fp == NULL) {
        fprintf(stderr, "공개키 파일 생성 실패: %s\n", pub_file);
        goto cleanup;
    }
    fwrite(public_key, 1, sig->length_public_key, pub_fp);
    fclose(pub_fp);

    // 비밀키 저장
    FILE *sec_fp = fopen(sec_file, "wb");
    if (sec_fp == NULL) {
        fprintf(stderr, "비밀키 파일 생성 실패: %s\n", sec_file);
        goto cleanup;
    }
    fwrite(secret_key, 1, sig->length_secret_key, sec_fp);
    fclose(sec_fp);

    printf("키 생성 완료!\n");
    printf("  공개키: %s (%zu bytes)\n", pub_file, sig->length_public_key);
    printf("  비밀키: %s (%zu bytes)\n", sec_file, sig->length_secret_key);

    ret = 0;

cleanup:
    if (sig) OQS_SIG_free(sig);
    if (public_key) {
        OQS_MEM_secure_free(public_key, sig ? sig->length_public_key : 0);
    }
    if (secret_key) {
        OQS_MEM_secure_free(secret_key, sig ? sig->length_secret_key : 0);
    }

    return ret;
}

/* 사용법 출력 */
void print_usage(const char *prog) {
    printf("사용법: %s [옵션]\n\n", prog);
    printf("옵션:\n");
    printf("  -t TYPE         키 타입 (kem 또는 sig)\n");
    printf("  -a ALGORITHM    알고리즘 이름\n");
    printf("  -p PUBLIC_KEY   공개키 출력 파일\n");
    printf("  -s SECRET_KEY   비밀키 출력 파일\n");
    printf("  -v              상세 출력\n");
    printf("  -l, --list      지원되는 알고리즘 목록 표시\n");
    printf("  -h, --help      도움말 표시\n\n");
    printf("예제:\n");
    printf("  # Kyber768 KEM 키 생성\n");
    printf("  %s -t kem -a Kyber768 -p kyber_pub.key -s kyber_sec.key\n\n", prog);
    printf("  # Dilithium3 서명 키 생성\n");
    printf("  %s -t sig -a Dilithium3 -p dilithium_pub.key -s dilithium_sec.key\n\n", prog);
    printf("  # 지원되는 알고리즘 목록\n");
    printf("  %s --list\n", prog);
}

int main(int argc, char **argv) {
    KeyGenConfig config = {0};
    config.verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "t:a:p:s:vlh")) != -1) {
        switch (opt) {
            case 't':
                if (strcmp(optarg, "kem") == 0) {
                    config.type = KEY_TYPE_KEM;
                } else if (strcmp(optarg, "sig") == 0) {
                    config.type = KEY_TYPE_SIG;
                } else {
                    fprintf(stderr, "오류: 잘못된 키 타입 '%s' (kem 또는 sig)\n", optarg);
                    return 1;
                }
                break;
            case 'a':
                config.algorithm = optarg;
                break;
            case 'p':
                config.output_public = optarg;
                break;
            case 's':
                config.output_secret = optarg;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'l':
                print_supported_algorithms();
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // --list 옵션 처리
    if (argc > 1 && strcmp(argv[1], "--list") == 0) {
        print_supported_algorithms();
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    // 필수 인자 확인
    if (config.algorithm == NULL || config.output_public == NULL || config.output_secret == NULL) {
        fprintf(stderr, "오류: 알고리즘(-a), 공개키(-p), 비밀키(-s) 옵션은 필수입니다.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // liboqs 초기화
    OQS_init();

    int ret;
    if (config.type == KEY_TYPE_KEM) {
        ret = generate_kem_keypair(config.algorithm, config.output_public,
                                   config.output_secret, config.verbose);
    } else {
        ret = generate_sig_keypair(config.algorithm, config.output_public,
                                   config.output_secret, config.verbose);
    }

    // liboqs 정리
    OQS_destroy();

    return ret;
}
