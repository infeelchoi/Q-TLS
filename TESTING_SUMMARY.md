# Q-TLS 테스트 및 벤치마크 도구 요약

## 생성된 파일 목록

### 1. 단위 테스트 (tests/unit/)
```
tests/unit/
├── test_kyber.c              (448 lines) - KYBER1024 암호화 테스트
├── test_dilithium.c          (520 lines) - DILITHIUM3 서명 테스트
├── test_handshake.c          (425 lines) - 핸드셰이크 프로토콜 테스트
├── test_session.c            (415 lines) - 세션 관리 및 보안 메모리 테스트
├── Makefile                            - 빌드 설정
└── run_tests.sh                        - 자동 테스트 실행 스크립트
```

**주요 테스트:**
- ✓ KYBER1024 키 생성, 캡슐화, 역캡슐화
- ✓ DILITHIUM3 키 생성, 서명, 검증
- ✓ 하이브리드 마스터 시크릿 유도
- ✓ 세션 키 유도 및 검증
- ✓ 보안 메모리 제로화
- ✓ 에러 처리 (NULL 포인터, 잘못된 입력)

### 2. 통합 테스트 (tests/integration/)
```
tests/integration/
├── test_server_client.c      (550 lines) - 서버-클라이언트 통신 테스트
├── test_mutual_tls.c         (280 lines) - 상호 TLS 인증 테스트
├── test_hsm_integration.c    (225 lines) - HSM 통합 테스트
├── test_qsign_integration.c  (310 lines) - QSIGN 프레임워크 통합
├── Makefile                            - 빌드 설정
└── README.md                           - 통합 테스트 가이드 (한국어)
```

**주요 시나리오:**
- ✓ TCP 소켓 기반 서버-클라이언트 연결
- ✓ 완전한 핸드셰이크 (KYBER + 키 유도)
- ✓ 양방향 인증 (mTLS)
- ✓ 인증서 검증 및 위조 거부
- ✓ HSM 시뮬레이션 (Luna HSM)
- ✓ QSIGN 워크플로우 통합

### 3. 성능 벤치마크 (tools/benchmark/)
```
tools/benchmark/
├── benchmark.c               (650 lines) - 주요 성능 벤치마크
├── benchmark_hsm.c           (45 lines)  - HSM 성능 벤치마크
├── Makefile                            - 빌드 설정 (-O3 최적화)
├── README.md                           - 벤치마크 가이드 (한국어)
└── run_benchmark.sh                    - 자동 벤치마크 스크립트
```

**측정 항목:**
- ✓ KYBER1024: keygen, encapsulate, decapsulate (ops/sec)
- ✓ DILITHIUM3: keygen, sign, verify (ops/sec, Mbps)
- ✓ 전체 핸드셰이크: 평균 시간 및 처리량
- ✓ 메모리 사용량 측정
- ✓ 워밍업 및 반복 측정 (통계적 정확도)

### 4. 보안 테스트 (tests/security/)
```
tests/security/
├── test_timing.c                 (280 lines) - 타이밍 공격 테스트
├── test_certificate_validation.c (190 lines) - 인증서 검증 보안
├── fuzz_handshake.c              (200 lines) - 퍼징 테스트
└── README.md                               - 보안 테스트 가이드 (한국어)
```

**보안 검증:**
- ✓ 상수 시간 연산 (타이밍 공격 방어)
- ✓ 메모리 제로화 타이밍 일관성
- ✓ 키 유도 타이밍 분석
- ✓ 인증서 검증 (정상/만료/위조/변조)
- ✓ 랜덤 입력 퍼징 (크래시 방지)

### 5. CI/CD 워크플로우 (.github/workflows/)
```
.github/workflows/
└── ci.yml                        (370 lines) - GitHub Actions 설정 (한국어 주석)
```

**CI/CD 파이프라인:**
- ✓ 자동 빌드 (Ubuntu latest)
- ✓ 단위 테스트 자동 실행
- ✓ 통합 테스트 자동 실행
- ✓ 보안 테스트 (타이밍, 퍼징)
- ✓ Valgrind 메모리 누수 검사
- ✓ 성능 벤치마크
- ✓ 코드 품질 검사 (cppcheck, clang-format)
- ✓ API 문서 자동 생성
- ✓ 릴리즈 빌드 및 배포

## 통계 요약

### 코드 통계
- **총 테스트 파일:** 13개
- **총 코드 라인:** 3,483 lines (주석 포함)
- **테스트 케이스:** 50+ 개
- **문서 파일:** 4개 (README.md, 한국어)

### 커버리지
- **단위 테스트:** 6개 주요 컴포넌트
- **통합 테스트:** 4개 시나리오
- **보안 테스트:** 3개 공격 벡터
- **벤치마크:** 7개 성능 지표

## 사용 방법

### 1. 단위 테스트 실행
```bash
cd /home/user/QSIGN/Q-TLS/tests/unit
make clean && make all
./run_tests.sh
```

### 2. 통합 테스트 실행
```bash
cd /home/user/QSIGN/Q-TLS/tests/integration
make clean && make all
make test
```

### 3. 보안 테스트 실행
```bash
cd /home/user/QSIGN/Q-TLS/tests/security

# 타이밍 공격 테스트
gcc -Wall -O2 -I../../include -o test_timing test_timing.c \
    -L../../build -lqtls -loqs -lcrypto -lm
LD_LIBRARY_PATH=../../build ./test_timing

# 인증서 검증 테스트
gcc -Wall -O2 -I../../include -o test_certificate_validation \
    test_certificate_validation.c -L../../build -lqtls -loqs -lcrypto
LD_LIBRARY_PATH=../../build ./test_certificate_validation

# 퍼징 테스트
gcc -Wall -O2 -I../../include -o fuzz_handshake fuzz_handshake.c \
    -L../../build -lqtls -loqs -lcrypto
LD_LIBRARY_PATH=../../build ./fuzz_handshake
```

### 4. 성능 벤치마크 실행
```bash
cd /home/user/QSIGN/Q-TLS/tools/benchmark
make clean && make all
./run_benchmark.sh
```

### 5. Valgrind 메모리 검사
```bash
cd /home/user/QSIGN/Q-TLS/tests/unit
./run_tests.sh --valgrind
```

## 주요 특징

### 한국어 지원
- ✓ 모든 주석 한국어 작성
- ✓ 테스트 메시지 한국어 출력
- ✓ README.md 한국어 문서
- ✓ 에러 메시지 한국어 설명

### 색상 출력
- 🟢 GREEN: 테스트 통과
- 🔴 RED: 테스트 실패
- 🟡 YELLOW: 진행 중 / 경고

### 자동화
- ✓ 자동 빌드 스크립트
- ✓ 자동 테스트 실행
- ✓ 자동 벤치마크 측정
- ✓ GitHub Actions CI/CD

### 보안 중심
- ✓ 타이밍 공격 방어 검증
- ✓ 메모리 누수 검사
- ✓ 퍼징 테스트
- ✓ 인증서 보안 검증

## 예상 출력 예시

### 단위 테스트
```
==========================================
  Q-TLS KYBER1024 단위 테스트
  ML-KEM-1024 암호화 알고리즘 검증
==========================================

[ RUN      ] test_kyber_keygen
[       OK ] test_kyber_keygen
[ RUN      ] test_kyber_encapsulate
[       OK ] test_kyber_encapsulate
...

==========================================
  모든 테스트 통과!
  통과: 6개
==========================================
```

### 성능 벤치마크
```
=========================================================
  Q-TLS 성능 벤치마크
  양자내성 암호화 알고리즘 성능 측정
=========================================================

KYBER1024 키 생성 벤치마크
  KYBER1024 keygen              평균:     1.23 ms  처리량:      813 ops/sec
  KYBER1024 encapsulate         평균:     1.45 ms  처리량:      690 ops/sec
  KYBER1024 decapsulate         평균:     1.38 ms  처리량:      725 ops/sec

DILITHIUM3 키 생성 벤치마크
  DILITHIUM3 keygen             평균:     2.34 ms  처리량:      427 ops/sec
  DILITHIUM3 sign               평균:     3.56 ms  처리량:      281 ops/sec    2.89 Mbps
  DILITHIUM3 verify             평균:     1.12 ms  처리량:      893 ops/sec    9.18 Mbps

전체 핸드셰이크 벤치마크
  전체 핸드셰이크               평균:     8.45 ms  처리량:      118 ops/sec

메모리 사용량:
  최대 메모리: 24576 KB
  증가량: 1024 KB
```

## 문제 해결

### 빌드 오류
1. liboqs가 설치되었는지 확인
2. LD_LIBRARY_PATH 설정 확인
3. include 경로 확인

### 테스트 실패
1. Q-TLS 라이브러리 먼저 빌드
2. 로그 파일 확인 (/tmp/test_*.log)
3. Valgrind로 메모리 문제 검사

### 성능 저하
1. CPU 가버너를 performance 모드로 설정
2. -O3 최적화 플래그 사용
3. AVX2 명령어 활성화

## 참고 자료

- [Q-TLS API 문서](/home/user/QSIGN/Q-TLS/docs/API.md)
- [liboqs 문서](https://github.com/open-quantum-safe/liboqs)
- [NIST PQC 표준](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [GitHub Actions 문서](https://docs.github.com/en/actions)

## 라이센스

Copyright 2025 QSIGN Project
Licensed under the Apache License, Version 2.0

---

**생성 일자:** 2025-11-16
**Q-TLS 버전:** 1.0.0
**작성자:** Claude (Anthropic AI)
