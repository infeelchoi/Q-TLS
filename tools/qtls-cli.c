/*
 * Q-TLS CLI 통합 도구
 * OpenSSL 스타일의 사용하기 쉬운 명령행 인터페이스
 *
 * 사용법:
 *   qtls keygen <algorithm> -o <output>
 *   qtls certgen ca|server|client -s <subject> -o <output>
 *   qtls quickstart -d <directory>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define VERSION "1.0.0"

/* 색상 정의 */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_CYAN    "\033[0;36m"

/* 유틸리티 함수 */
void print_success(const char *msg) {
    printf("%s✓ %s%s\n", COLOR_GREEN, msg, COLOR_RESET);
}

void print_error(const char *msg) {
    fprintf(stderr, "%s✗ %s%s\n", COLOR_RED, msg, COLOR_RESET);
}

void print_info(const char *msg) {
    printf("%sℹ %s%s\n", COLOR_CYAN, msg, COLOR_RESET);
}

void print_warning(const char *msg) {
    printf("%s⚠ %s%s\n", COLOR_YELLOW, msg, COLOR_RESET);
}

/* 메인 사용법 */
void print_usage(const char *prog) {
    printf("%sQ-TLS CLI v%s%s - 양자 내성 암호화 통합 도구\n\n", COLOR_CYAN, VERSION, COLOR_RESET);
    printf("사용법: %s <명령어> [옵션]\n\n", prog);
    printf("%s명령어:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  %skeygen%s      키 쌍 생성 (Kyber, Dilithium)\n", COLOR_GREEN, COLOR_RESET);
    printf("  %scertgen%s    인증서 생성 (CA, 서버, 클라이언트)\n", COLOR_GREEN, COLOR_RESET);
    printf("  %squickstart%s  빠른 시작 - CA + 서버 + 클라이언트 한번에 생성\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sverify%s     인증서/키 검증\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sinfo%s       인증서/키 정보 조회\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sversion%s    버전 정보\n", COLOR_GREEN, COLOR_RESET);
    printf("  %shelp%s       도움말\n", COLOR_GREEN, COLOR_RESET);
    printf("\n");
    printf("%s빠른 예제:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  # 전체 PKI 인프라 구축 (CA + 서버 + 클라이언트)\n");
    printf("  %s quickstart -d ./my-pki\n\n", prog);
    printf("  # Kyber768 키 생성\n");
    printf("  %s keygen kyber768 -o mykey\n\n", prog);
    printf("  # 서버 인증서 생성\n");
    printf("  %s certgen server -cn server.example.com -o server\n\n", prog);
    printf("상세 도움말: %s <명령어> --help\n", prog);
}

/* keygen 명령어 도움말 */
void print_keygen_help(const char *prog) {
    printf("%sQ-TLS 키 생성%s\n\n", COLOR_CYAN, COLOR_RESET);
    printf("사용법: %s keygen <알고리즘> [옵션]\n\n", prog);
    printf("%s지원 알고리즘:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  KEM (키 캡슐화):\n");
    printf("    kyber512, kyber768, kyber1024\n");
    printf("  서명:\n");
    printf("    dilithium2, dilithium3, dilithium5\n\n");
    printf("%s옵션:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  -o, --output NAME    출력 파일명 (확장자 제외)\n");
    printf("  -d, --dir PATH       출력 디렉토리 (기본: 현재 디렉토리)\n");
    printf("  -v, --verbose        상세 출력\n");
    printf("  -h, --help           도움말\n\n");
    printf("%s예제:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  %s keygen kyber768 -o mykey\n", prog);
    printf("    → mykey.pub, mykey.key 생성\n\n");
    printf("  %s keygen dilithium3 -o signing -d ./keys\n", prog);
    printf("    → ./keys/signing.pub, ./keys/signing.key 생성\n");
}

/* certgen 명령어 도움말 */
void print_certgen_help(const char *prog) {
    printf("%sQ-TLS 인증서 생성%s\n\n", COLOR_CYAN, COLOR_RESET);
    printf("사용법: %s certgen <타입> [옵션]\n\n", prog);
    printf("%s인증서 타입:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  ca         CA (인증 기관) 인증서\n");
    printf("  server     서버 인증서\n");
    printf("  client     클라이언트 인증서 (상호 TLS용)\n\n");
    printf("%s옵션:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  -cn, --common-name NAME  Common Name (필수)\n");
    printf("  -o, --output NAME        출력 파일명 (확장자 제외)\n");
    printf("  -d, --dir PATH           출력 디렉토리 (기본: 현재)\n");
    printf("  -a, --algorithm ALG      알고리즘 (dilithium3, dilithium5, rsa)\n");
    printf("  --days DAYS              유효 기간 (기본: CA=3650, 기타=365)\n");
    printf("  --ca-cert PATH           CA 인증서 경로 (server/client용)\n");
    printf("  --ca-key PATH            CA 키 경로 (server/client용)\n");
    printf("  --san DOMAIN             SAN 도메인 추가 (server용, 반복 가능)\n");
    printf("  -v, --verbose            상세 출력\n");
    printf("  -h, --help               도움말\n\n");
    printf("%s예제:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  # CA 생성\n");
    printf("  %s certgen ca -cn \"My Root CA\" -o ca\n\n", prog);
    printf("  # 서버 인증서 생성\n");
    printf("  %s certgen server -cn server.example.com \\\n", prog);
    printf("       --ca-cert ca.crt --ca-key ca.key \\\n");
    printf("       --san www.example.com --san api.example.com \\\n");
    printf("       -o server\n\n");
    printf("  # 클라이언트 인증서 생성\n");
    printf("  %s certgen client -cn \"client-001\" \\\n", prog);
    printf("       --ca-cert ca.crt --ca-key ca.key -o client\n");
}

/* quickstart 명령어 도움말 */
void print_quickstart_help(const char *prog) {
    printf("%sQ-TLS 빠른 시작%s\n\n", COLOR_CYAN, COLOR_RESET);
    printf("CA, 서버, 클라이언트 인증서를 한 번에 생성합니다.\n\n");
    printf("사용법: %s quickstart [옵션]\n\n", prog);
    printf("%s옵션:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  -d, --dir PATH           출력 디렉토리 (기본: ./qtls-pki)\n");
    printf("  -cn, --server-cn NAME    서버 CN (기본: localhost)\n");
    printf("  -a, --algorithm ALG      알고리즘 (기본: dilithium3)\n");
    printf("  -v, --verbose            상세 출력\n");
    printf("  -h, --help               도움말\n\n");
    printf("%s생성되는 파일:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  ca.crt, ca.key           CA 인증서 및 키\n");
    printf("  server.crt, server.key   서버 인증서 및 키\n");
    printf("  client.crt, client.key   클라이언트 인증서 및 키\n");
    printf("  README.txt               사용 가이드\n\n");
    printf("%s예제:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  %s quickstart -d ./my-pki -cn myserver.local\n", prog);
}

/* 디렉토리 생성 */
int ensure_directory(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0755) != 0) {
            print_error("디렉토리 생성 실패");
            return -1;
        }
    }
    return 0;
}

/* 시스템 명령 실행 */
int run_command(const char *cmd, int verbose) {
    if (verbose) {
        print_info(cmd);
    }
    int ret = system(cmd);
    return ret;
}

/* keygen 명령어 처리 */
int cmd_keygen(int argc, char **argv) {
    if (argc < 3) {
        print_error("알고리즘을 지정하세요");
        print_keygen_help(argv[0]);
        return 1;
    }

    char *algorithm = argv[2];
    char *output = "qtls_key";
    char *dir = ".";
    int verbose = 0;

    // 옵션 파싱
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dir") == 0) {
            if (i + 1 < argc) dir = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_keygen_help(argv[0]);
            return 0;
        }
    }

    // 디렉토리 생성
    ensure_directory(dir);

    // 키 타입 결정
    char *key_type = NULL;
    char *alg_name = NULL;

    if (strncmp(algorithm, "kyber", 5) == 0) {
        key_type = "kem";
        if (strcmp(algorithm, "kyber512") == 0) alg_name = "Kyber512";
        else if (strcmp(algorithm, "kyber768") == 0) alg_name = "Kyber768";
        else if (strcmp(algorithm, "kyber1024") == 0) alg_name = "Kyber1024";
    } else if (strncmp(algorithm, "dilithium", 9) == 0) {
        key_type = "sig";
        if (strcmp(algorithm, "dilithium2") == 0) alg_name = "Dilithium2";
        else if (strcmp(algorithm, "dilithium3") == 0) alg_name = "Dilithium3";
        else if (strcmp(algorithm, "dilithium5") == 0) alg_name = "Dilithium5";
    }

    if (key_type == NULL || alg_name == NULL) {
        print_error("지원하지 않는 알고리즘입니다");
        printf("지원: kyber512, kyber768, kyber1024, dilithium2, dilithium3, dilithium5\n");
        return 1;
    }

    printf("%s%s 키 쌍 생성 중...%s\n", COLOR_YELLOW, alg_name, COLOR_RESET);

    // keygen 명령 실행
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "keygen -t %s -a %s -p %s/%s.pub -s %s/%s.key %s",
             key_type, alg_name, dir, output, dir, output,
             verbose ? "-v" : "");

    if (run_command(cmd, verbose) == 0) {
        print_success("키 생성 완료!");
        printf("  공개키: %s/%s.pub\n", dir, output);
        printf("  비밀키: %s/%s.key\n", dir, output);
        return 0;
    } else {
        print_error("키 생성 실패");
        return 1;
    }
}

/* certgen 명령어 처리 */
int cmd_certgen(int argc, char **argv) {
    if (argc < 3) {
        print_error("인증서 타입을 지정하세요 (ca, server, client)");
        print_certgen_help(argv[0]);
        return 1;
    }

    char *cert_type = argv[2];
    char *cn = NULL;
    char *output = NULL;
    char *dir = ".";
    char *algorithm = "dilithium3";
    char *ca_cert = NULL;
    char *ca_key = NULL;
    int days = -1;
    char san_list[10][256] = {0};
    int san_count = 0;
    int verbose = 0;

    // 기본 출력 파일명
    if (strcmp(cert_type, "ca") == 0) output = "ca";
    else if (strcmp(cert_type, "server") == 0) output = "server";
    else if (strcmp(cert_type, "client") == 0) output = "client";

    // 옵션 파싱
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-cn") == 0 || strcmp(argv[i], "--common-name") == 0) {
            if (i + 1 < argc) cn = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dir") == 0) {
            if (i + 1 < argc) dir = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 < argc) algorithm = argv[++i];
        } else if (strcmp(argv[i], "--days") == 0) {
            if (i + 1 < argc) days = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ca-cert") == 0) {
            if (i + 1 < argc) ca_cert = argv[++i];
        } else if (strcmp(argv[i], "--ca-key") == 0) {
            if (i + 1 < argc) ca_key = argv[++i];
        } else if (strcmp(argv[i], "--san") == 0) {
            if (i + 1 < argc && san_count < 10) {
                strncpy(san_list[san_count++], argv[++i], 255);
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_certgen_help(argv[0]);
            return 0;
        }
    }

    // 필수 옵션 확인
    if (cn == NULL) {
        print_error("Common Name (-cn)을 지정하세요");
        return 1;
    }

    // 디렉토리 생성
    ensure_directory(dir);

    // 기본 days 설정
    if (days == -1) {
        days = (strcmp(cert_type, "ca") == 0) ? 3650 : 365;
    }

    printf("%s%s 인증서 생성 중...%s\n", COLOR_YELLOW,
           strcmp(cert_type, "ca") == 0 ? "CA" :
           strcmp(cert_type, "server") == 0 ? "서버" : "클라이언트",
           COLOR_RESET);

    // Subject 구성
    char subject[512];
    snprintf(subject, sizeof(subject), "/C=KR/ST=Seoul/O=Q-TLS/CN=%s", cn);

    // certgen 명령 실행
    char cmd[2048];
    int offset = snprintf(cmd, sizeof(cmd),
                         "certgen -t %s -a %s -s \"%s\" -d %d -o %s/%s.crt -k %s/%s.key",
                         cert_type, algorithm, subject, days, dir, output, dir, output);

    // CA 인증서/키 추가 (server, client용)
    if (strcmp(cert_type, "server") == 0 || strcmp(cert_type, "client") == 0) {
        if (ca_cert == NULL || ca_key == NULL) {
            print_error("server/client 인증서는 --ca-cert, --ca-key가 필요합니다");
            return 1;
        }
        offset += snprintf(cmd + offset, sizeof(cmd) - offset,
                          " -c %s -K %s", ca_cert, ca_key);
    }

    // SAN 추가 (server용)
    if (strcmp(cert_type, "server") == 0) {
        // CN을 기본 SAN으로 추가
        offset += snprintf(cmd + offset, sizeof(cmd) - offset, " -n %s", cn);

        for (int i = 0; i < san_count; i++) {
            offset += snprintf(cmd + offset, sizeof(cmd) - offset,
                             " -n %s", san_list[i]);
        }
    }

    if (run_command(cmd, verbose) == 0) {
        print_success("인증서 생성 완료!");
        printf("  인증서: %s/%s.crt\n", dir, output);
        printf("  키: %s/%s.key\n", dir, output);
        return 0;
    } else {
        print_error("인증서 생성 실패");
        return 1;
    }
}

/* quickstart 명령어 처리 */
int cmd_quickstart(int argc, char **argv) {
    char *dir = "./qtls-pki";
    char *server_cn = "localhost";
    char *algorithm = "dilithium3";
    int verbose = 0;

    // 옵션 파싱
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dir") == 0) {
            if (i + 1 < argc) dir = argv[++i];
        } else if (strcmp(argv[i], "-cn") == 0 || strcmp(argv[i], "--server-cn") == 0) {
            if (i + 1 < argc) server_cn = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 < argc) algorithm = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_quickstart_help(argv[0]);
            return 0;
        }
    }

    printf("%s=== Q-TLS 빠른 시작 ===%s\n\n", COLOR_CYAN, COLOR_RESET);
    printf("디렉토리: %s\n", dir);
    printf("서버 CN: %s\n", server_cn);
    printf("알고리즘: %s\n\n", algorithm);

    // 디렉토리 생성
    if (ensure_directory(dir) != 0) {
        return 1;
    }

    char cmd[1024];

    // 1. CA 생성
    printf("%s[1/3] CA 인증서 생성%s\n", COLOR_YELLOW, COLOR_RESET);
    snprintf(cmd, sizeof(cmd),
             "certgen -t ca -a %s -s \"/C=KR/O=Q-TLS/CN=Q-TLS Root CA\" "
             "-d 3650 -o %s/ca.crt -k %s/ca.key %s",
             algorithm, dir, dir, verbose ? "" : "2>/dev/null");

    if (run_command(cmd, verbose) != 0) {
        print_error("CA 생성 실패");
        return 1;
    }
    print_success("CA 생성 완료");

    // 2. 서버 인증서 생성
    printf("\n%s[2/3] 서버 인증서 생성%s\n", COLOR_YELLOW, COLOR_RESET);
    snprintf(cmd, sizeof(cmd),
             "certgen -t server -a %s -s \"/C=KR/O=Q-TLS/CN=%s\" "
             "-c %s/ca.crt -K %s/ca.key -o %s/server.crt -k %s/server.key "
             "-n %s -n www.%s %s",
             algorithm, server_cn, dir, dir, dir, dir,
             server_cn, server_cn, verbose ? "" : "2>/dev/null");

    if (run_command(cmd, verbose) != 0) {
        print_error("서버 인증서 생성 실패");
        return 1;
    }
    print_success("서버 인증서 생성 완료");

    // 3. 클라이언트 인증서 생성
    printf("\n%s[3/3] 클라이언트 인증서 생성%s\n", COLOR_YELLOW, COLOR_RESET);
    snprintf(cmd, sizeof(cmd),
             "certgen -t client -a %s -s \"/C=KR/O=Q-TLS/CN=Q-TLS Client\" "
             "-c %s/ca.crt -K %s/ca.key -o %s/client.crt -k %s/client.key %s",
             algorithm, dir, dir, dir, dir, verbose ? "" : "2>/dev/null");

    if (run_command(cmd, verbose) != 0) {
        print_error("클라이언트 인증서 생성 실패");
        return 1;
    }
    print_success("클라이언트 인증서 생성 완료");

    // README 생성
    char readme_path[512];
    snprintf(readme_path, sizeof(readme_path), "%s/README.txt", dir);
    FILE *readme = fopen(readme_path, "w");
    if (readme) {
        fprintf(readme, "Q-TLS PKI 인프라\n");
        fprintf(readme, "================\n\n");
        fprintf(readme, "생성일: ");
        system("date >> " readme_path);
        fprintf(readme, "\n파일 목록:\n");
        fprintf(readme, "  ca.crt, ca.key         - CA 인증서 및 키\n");
        fprintf(readme, "  server.crt, server.key - 서버 인증서 및 키\n");
        fprintf(readme, "  client.crt, client.key - 클라이언트 인증서 및 키\n\n");
        fprintf(readme, "사용 예제:\n");
        fprintf(readme, "  서버 실행:\n");
        fprintf(readme, "    qtls-server --cert server.crt --key server.key --ca ca.crt\n\n");
        fprintf(readme, "  클라이언트 연결:\n");
        fprintf(readme, "    qtls-client --cert client.crt --key client.key --ca ca.crt\n\n");
        fprintf(readme, "보안:\n");
        fprintf(readme, "  chmod 600 *.key  # 키 파일 권한 설정\n");
        fclose(readme);
    }

    printf("\n%s=== 완료! ===%s\n", COLOR_GREEN, COLOR_RESET);
    printf("\n생성된 파일:\n");
    printf("  %s/ca.crt, ca.key\n", dir);
    printf("  %s/server.crt, server.key\n", dir);
    printf("  %s/client.crt, client.key\n", dir);
    printf("  %s/README.txt\n", dir);
    printf("\n%s권장:%s 비밀키 권한 설정\n", COLOR_YELLOW, COLOR_RESET);
    printf("  chmod 600 %s/*.key\n", dir);

    return 0;
}

/* 버전 정보 */
int cmd_version() {
    printf("Q-TLS CLI v%s\n", VERSION);
    printf("양자 내성 암호화 통합 도구\n");
    printf("Copyright (c) 2024 Q-TLS Project\n");
    return 0;
}

/* 메인 함수 */
int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    char *command = argv[1];

    if (strcmp(command, "keygen") == 0) {
        return cmd_keygen(argc, argv);
    } else if (strcmp(command, "certgen") == 0) {
        return cmd_certgen(argc, argv);
    } else if (strcmp(command, "quickstart") == 0) {
        return cmd_quickstart(argc, argv);
    } else if (strcmp(command, "version") == 0 || strcmp(command, "-v") == 0 || strcmp(command, "--version") == 0) {
        return cmd_version();
    } else if (strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        print_error("알 수 없는 명령어입니다");
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
