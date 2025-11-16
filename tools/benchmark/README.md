# Q-TLS 성능 벤치마크

Q-TLS의 암호화 연산 성능을 측정하는 벤치마크 도구입니다.

## 벤치마크 항목

### 1. KYBER1024 (ML-KEM-1024)
- **키 생성**: 공개키/비밀키 쌍 생성 시간
- **캡슐화**: 공유 비밀 캡슐화 시간
- **역캡슐화**: 암호문 해독 시간

### 2. DILITHIUM3 (ML-DSA-65)
- **키 생성**: 서명키 쌍 생성 시간
- **서명**: 메시지 서명 시간
- **검증**: 서명 검증 시간

### 3. 전체 핸드셰이크
- KYBER 키 교환 + 하이브리드 시크릿 유도 + 세션 키 유도
- 전체 TLS 핸드셰이크 시간

## 사용법

```bash
# 빌드
make clean
make all

# 실행
make run

# 또는 직접 실행
LD_LIBRARY_PATH=../../build ./benchmark
```

## 출력 예시

```
=========================================================
  Q-TLS 성능 벤치마크
  양자내성 암호화 알고리즘 성능 측정
=========================================================

설정:
  워밍업 반복 횟수: 10
  벤치마크 반복 횟수: 100
  메시지 크기: 1024 bytes

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

=========================================================
  벤치마크 완료!
=========================================================
```

## 성능 최적화

### 컴파일 옵션
```bash
# 최대 성능 (CPU 아키텍처 최적화)
CFLAGS="-O3 -march=native" make

# AVX2 지원
CFLAGS="-O3 -mavx2" make

# 디버그 정보 포함
CFLAGS="-O2 -g" make
```

### liboqs 최적화
```bash
# liboqs 빌드 시 AVX2 활성화
cd /path/to/liboqs
mkdir build && cd build
cmake -DOQS_USE_AVX2_INSTRUCTIONS=ON ..
make && sudo make install
```

## HSM 벤치마크

Luna HSM을 사용한 성능 측정:

```bash
./benchmark_hsm
```

참고: 실제 HSM 하드웨어가 필요합니다.

## 비교 분석

### 고전 암호와 비교
- RSA-2048 키 생성: ~50 ms
- KYBER1024 키 생성: ~1.2 ms (약 40배 빠름)
- ECDSA-P384 서명: ~2 ms
- DILITHIUM3 서명: ~3.5 ms (비슷한 수준)

### 보안 레벨
- KYBER1024: NIST Level 5 (AES-256 상당)
- DILITHIUM3: NIST Level 3 (AES-192 상당)

## 문제 해결

### 성능 저하
```bash
# CPU 주파수 확인
cat /proc/cpuinfo | grep MHz

# CPU 가버너 설정 (성능 모드)
sudo cpupower frequency-set -g performance
```

### 메모리 부족
```bash
# 스왑 확인
free -h

# ulimit 증가
ulimit -s unlimited
```

## 참고 자료

- [liboqs 벤치마크](https://github.com/open-quantum-safe/liboqs/wiki/Performance)
- [NIST PQC 표준](https://csrc.nist.gov/projects/post-quantum-cryptography)
