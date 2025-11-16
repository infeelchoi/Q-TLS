/*
 * Q-TLS HSM 키 생성 도구
 * Thales Luna HSM을 사용한 양자 내성 키 생성
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_HSM
#include <cryptoki.h>

#define LUNA_LIB "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"

typedef struct {
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id;
    char *pin;
    char *label;
    int key_type;  // 0: Kyber, 1: Dilithium
    int verbose;
} HSMKeyGenConfig;

/* PKCS#11 함수 포인터 */
CK_FUNCTION_LIST *p11_functions = NULL;

/* HSM 초기화 */
int hsm_init(const char *lib_path) {
    CK_RV rv;
    CK_C_GetFunctionList pGetFunctionList;

    // PKCS#11 라이브러리 로드 (실제로는 dlopen 사용)
    printf("HSM 라이브러리 로드: %s\n", lib_path);

    // 함수 리스트 가져오기
    rv = C_GetFunctionList(&p11_functions);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetFunctionList 실패: 0x%lx\n", rv);
        return -1;
    }

    // PKCS#11 초기화
    rv = p11_functions->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        fprintf(stderr, "C_Initialize 실패: 0x%lx\n", rv);
        return -1;
    }

    printf("HSM 초기화 성공\n");
    return 0;
}

/* 슬롯 목록 조회 */
int hsm_list_slots() {
    CK_RV rv;
    CK_SLOT_ID_PTR slots = NULL;
    CK_ULONG slot_count = 0;

    // 슬롯 개수 조회
    rv = p11_functions->C_GetSlotList(CK_TRUE, NULL, &slot_count);
    if (rv != CKR_OK) {
        fprintf(stderr, "슬롯 개수 조회 실패: 0x%lx\n", rv);
        return -1;
    }

    printf("사용 가능한 슬롯: %lu개\n", slot_count);

    if (slot_count == 0) {
        printf("사용 가능한 HSM 슬롯이 없습니다.\n");
        return 0;
    }

    // 슬롯 목록 조회
    slots = malloc(sizeof(CK_SLOT_ID) * slot_count);
    rv = p11_functions->C_GetSlotList(CK_TRUE, slots, &slot_count);
    if (rv != CKR_OK) {
        free(slots);
        return -1;
    }

    for (CK_ULONG i = 0; i < slot_count; i++) {
        CK_SLOT_INFO slot_info;
        rv = p11_functions->C_GetSlotInfo(slots[i], &slot_info);
        if (rv == CKR_OK) {
            printf("  슬롯 %lu: %.64s\n", slots[i], slot_info.slotDescription);
        }
    }

    free(slots);
    return 0;
}

/* 세션 열기 */
int hsm_open_session(HSMKeyGenConfig *config) {
    CK_RV rv;

    // 세션 열기
    rv = p11_functions->C_OpenSession(config->slot_id,
                                      CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                      NULL, NULL, &config->session);
    if (rv != CKR_OK) {
        fprintf(stderr, "세션 열기 실패: 0x%lx\n", rv);
        return -1;
    }

    // 로그인
    rv = p11_functions->C_Login(config->session, CKU_USER,
                                (CK_UTF8CHAR *)config->pin,
                                strlen(config->pin));
    if (rv != CKR_OK) {
        fprintf(stderr, "로그인 실패: 0x%lx\n", rv);
        p11_functions->C_CloseSession(config->session);
        return -1;
    }

    if (config->verbose) {
        printf("HSM 세션 열림 (슬롯 %lu)\n", config->slot_id);
    }

    return 0;
}

/* Kyber 키 쌍 생성 (HSM) */
int hsm_generate_kyber_keypair(HSMKeyGenConfig *config) {
    CK_RV rv;
    CK_OBJECT_HANDLE pub_key, priv_key;
    CK_MECHANISM mech = {CKM_KYBER768_KEY_PAIR_GEN, NULL, 0};

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_ATTRIBUTE pub_template[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, config->label, strlen(config->label)}
    };

    CK_ATTRIBUTE priv_template[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_DECRYPT, &ck_true, sizeof(ck_true)},
        {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
        {CKA_LABEL, config->label, strlen(config->label)}
    };

    printf("Kyber768 키 쌍 생성 중 (HSM)...\n");

    rv = p11_functions->C_GenerateKeyPair(config->session, &mech,
                                         pub_template, 3,
                                         priv_template, 6,
                                         &pub_key, &priv_key);

    if (rv != CKR_OK) {
        fprintf(stderr, "키 생성 실패: 0x%lx\n", rv);
        fprintf(stderr, "참고: HSM이 Kyber를 지원하는지 확인하세요.\n");
        return -1;
    }

    printf("Kyber768 키 생성 완료!\n");
    printf("  공개키 핸들: %lu\n", pub_key);
    printf("  비밀키 핸들: %lu\n", priv_key);
    printf("  레이블: %s\n", config->label);

    return 0;
}

/* Dilithium 키 쌍 생성 (HSM) */
int hsm_generate_dilithium_keypair(HSMKeyGenConfig *config) {
    CK_RV rv;
    CK_OBJECT_HANDLE pub_key, priv_key;
    CK_MECHANISM mech = {CKM_DILITHIUM3_KEY_PAIR_GEN, NULL, 0};

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_ATTRIBUTE pub_template[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_VERIFY, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, config->label, strlen(config->label)}
    };

    CK_ATTRIBUTE priv_template[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
        {CKA_LABEL, config->label, strlen(config->label)}
    };

    printf("Dilithium3 키 쌍 생성 중 (HSM)...\n");

    rv = p11_functions->C_GenerateKeyPair(config->session, &mech,
                                         pub_template, 3,
                                         priv_template, 6,
                                         &pub_key, &priv_key);

    if (rv != CKR_OK) {
        fprintf(stderr, "키 생성 실패: 0x%lx\n", rv);
        fprintf(stderr, "참고: HSM이 Dilithium을 지원하는지 확인하세요.\n");
        return -1;
    }

    printf("Dilithium3 키 생성 완료!\n");
    printf("  공개키 핸들: %lu\n", pub_key);
    printf("  비밀키 핸들: %lu\n", priv_key);
    printf("  레이블: %s\n", config->label);

    return 0;
}

/* 세션 닫기 */
void hsm_close_session(HSMKeyGenConfig *config) {
    p11_functions->C_Logout(config->session);
    p11_functions->C_CloseSession(config->session);
}

/* HSM 정리 */
void hsm_cleanup() {
    if (p11_functions) {
        p11_functions->C_Finalize(NULL);
    }
}

#endif /* ENABLE_HSM */

/* 사용법 출력 */
void print_usage(const char *prog) {
    printf("사용법: %s [옵션]\n\n", prog);
    printf("옵션:\n");
    printf("  -t TYPE         키 타입 (kyber 또는 dilithium)\n");
    printf("  -s SLOT_ID      HSM 슬롯 ID\n");
    printf("  -p PIN          HSM PIN\n");
    printf("  -l LABEL        키 레이블\n");
    printf("  -v              상세 출력\n");
    printf("  --list-slots    사용 가능한 슬롯 목록 표시\n");
    printf("  -h, --help      도움말 표시\n\n");
    printf("예제:\n");
    printf("  # 슬롯 목록 조회\n");
    printf("  %s --list-slots\n\n", prog);
    printf("  # Kyber768 키 생성\n");
    printf("  %s -t kyber -s 0 -p 1234 -l \"kyber-key-1\"\n\n", prog);
    printf("  # Dilithium3 키 생성\n");
    printf("  %s -t dilithium -s 0 -p 1234 -l \"dilithium-key-1\"\n", prog);
}

int main(int argc, char **argv) {
#ifndef ENABLE_HSM
    fprintf(stderr, "이 도구는 HSM 지원이 비활성화된 상태로 빌드되었습니다.\n");
    fprintf(stderr, "HSM 지원을 활성화하려면 -DENABLE_HSM 플래그로 컴파일하세요.\n");
    return 1;
#else
    HSMKeyGenConfig config = {0};
    config.slot_id = 0;
    config.verbose = 0;
    config.key_type = 0;  // Kyber

    int opt;
    int list_slots = 0;

    // 긴 옵션 처리
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list-slots") == 0) {
            list_slots = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    while ((opt = getopt(argc, argv, "t:s:p:l:vh")) != -1) {
        switch (opt) {
            case 't':
                if (strcmp(optarg, "kyber") == 0) {
                    config.key_type = 0;
                } else if (strcmp(optarg, "dilithium") == 0) {
                    config.key_type = 1;
                } else {
                    fprintf(stderr, "오류: 잘못된 키 타입 '%s'\n", optarg);
                    return 1;
                }
                break;
            case 's':
                config.slot_id = atoi(optarg);
                break;
            case 'p':
                config.pin = optarg;
                break;
            case 'l':
                config.label = optarg;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // HSM 초기화
    if (hsm_init(LUNA_LIB) != 0) {
        return 1;
    }

    // 슬롯 목록 표시
    if (list_slots) {
        hsm_list_slots();
        hsm_cleanup();
        return 0;
    }

    // 필수 인자 확인
    if (config.pin == NULL || config.label == NULL) {
        fprintf(stderr, "오류: PIN(-p)과 레이블(-l)은 필수입니다.\n\n");
        print_usage(argv[0]);
        hsm_cleanup();
        return 1;
    }

    // 세션 열기
    if (hsm_open_session(&config) != 0) {
        hsm_cleanup();
        return 1;
    }

    // 키 생성
    int ret;
    if (config.key_type == 0) {
        ret = hsm_generate_kyber_keypair(&config);
    } else {
        ret = hsm_generate_dilithium_keypair(&config);
    }

    // 정리
    hsm_close_session(&config);
    hsm_cleanup();

    return ret;
#endif
}
