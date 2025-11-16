# Q-TLS 통합 테스트

Q-TLS의 전체 시스템 통합 기능을 검증하는 테스트 스위트입니다.

## 테스트 목록

### 1. test_server_client
**서버-클라이언트 통합 테스트**
- TCP 소켓 기반 서버-클라이언트 연결
- KYBER1024 키 교환
- 하이브리드 핸드셰이크 (ECDHE + KYBER)
- 세션 키 유도 및 검증
- 양방향 데이터 전송

실행:
```bash
make test_server_client
LD_LIBRARY_PATH=../../build ./test_server_client
```

### 2. test_mutual_tls
**상호 TLS (mTLS) 테스트**
- DILITHIUM3 기반 인증서 서명 및 검증
- 서버 인증서 검증
- 클라이언트 인증서 검증
- 양방향 인증 (mutual authentication)
- 위조 인증서 거부

실행:
```bash
make test_mutual_tls
LD_LIBRARY_PATH=../../build ./test_mutual_tls
```

### 3. test_hsm_integration
**HSM 통합 테스트**
- Luna HSM (PKCS#11) 연동
- HSM 내부 키 생성
- HSM을 사용한 KYBER 역캡슐화
- HSM을 사용한 DILITHIUM 서명
- 비밀키 보호 (HSM 외부 노출 방지)

참고: 실제 HSM 하드웨어가 없으면 시뮬레이션 모드로 동작합니다.

실행:
```bash
make test_hsm_integration
LD_LIBRARY_PATH=../../build ./test_hsm_integration
```

### 4. test_qsign_integration
**QSIGN 프레임워크 통합 테스트**
- QSIGN 어댑터 초기화
- 정책 엔진 연동
- 인증서 관리 통합
- 전체 워크플로우 검증
- 보안 레벨 확인

실행:
```bash
make test_qsign_integration
LD_LIBRARY_PATH=../../build ./test_qsign_integration
```

## 전체 테스트 실행

모든 통합 테스트를 한 번에 실행:
```bash
make clean
make all
make test
```

## 테스트 환경

### 필수 요구사항
- liboqs (KYBER1024, DILITHIUM3 지원)
- OpenSSL 3.x (ECDHE, HKDF 지원)
- pthread (멀티스레드 테스트)

### 선택 요구사항
- Luna HSM (PKCS#11) - HSM 테스트용
- SoftHSM - HSM 시뮬레이션용

## 테스트 시나리오

### 시나리오 1: 기본 핸드셰이크
1. 서버: KYBER1024 키 생성
2. 클라이언트: 서버 공개키로 캡슐화
3. 서버: 암호문 역캡슐화
4. 양쪽: 하이브리드 마스터 시크릿 유도
5. 양쪽: 세션 키 유도
6. 검증: 모든 공유 비밀과 키 일치

### 시나리오 2: 상호 인증
1. CA: DILITHIUM3 키 생성
2. CA: 서버 인증서 서명
3. CA: 클라이언트 인증서 서명
4. 클라이언트: 서버 인증서 검증
5. 서버: 클라이언트 인증서 검증
6. 검증: 양방향 인증 성공

### 시나리오 3: HSM 사용
1. HSM: KYBER1024 키 생성 (HSM 내부)
2. 클라이언트: 캡슐화
3. HSM: 역캡슐화 (비밀키 노출 없음)
4. 검증: 공유 비밀 일치

## 문제 해결

### 컴파일 오류
```bash
# 라이브러리 경로 확인
export LD_LIBRARY_PATH=/usr/local/lib:../../build

# 헤더 파일 확인
ls -l ../../include/qtls/qtls.h
```

### 실행 오류
```bash
# 라이브러리 로드 확인
ldd ./test_server_client

# 포트 사용 중 에러
# 다른 프로세스가 18443 포트를 사용하는지 확인
netstat -tlnp | grep 18443
```

### HSM 테스트
```bash
# SoftHSM 설치 (테스트용)
sudo apt-get install softhsm2

# SoftHSM 초기화
softhsm2-util --init-token --slot 0 --label "Q-TLS-Test"
```

## 성공 기준

- 모든 테스트 PASS
- 메모리 누수 없음 (valgrind 검증)
- 공유 비밀 및 세션 키 일치
- 인증서 검증 성공
- 위조 인증서 올바르게 거부

## 추가 정보

- 테스트 로그: `/tmp/test_*.log`
- 디버그 모드: `ENABLE_LOGGING=1 make`
- Valgrind 검사: `valgrind --leak-check=full ./test_*`

## 참고 문서

- [Q-TLS API 문서](../../docs/API.md)
- [QSIGN 통합 가이드](../../docs/QSIGN_Integration.md)
- [HSM 설정 가이드](../../docs/HSM_Configuration.md)
