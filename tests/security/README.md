# Q-TLS 보안 테스트

Q-TLS의 보안 특성을 검증하는 테스트 스위트입니다.

## 테스트 목록

### 1. test_timing
**타이밍 공격 방어 테스트**
- 상수 시간 연산 검증
- KYBER 역캡슐화 타이밍 분석
- 메모리 제로화 타이밍 일관성
- 키 유도 타이밍 일관성

```bash
gcc -Wall -O2 -I../../include -o test_timing test_timing.c \
    -L../../build -lqtls -loqs -lcrypto -lm
LD_LIBRARY_PATH=../../build ./test_timing
```

### 2. test_certificate_validation
**인증서 검증 보안 테스트**
- 정상 인증서 검증
- 만료된 인증서 거부
- 위조 CA 서명 거부
- 변조된 인증서 감지
- 자체 서명 인증서

```bash
gcc -Wall -O2 -I../../include -o test_certificate_validation \
    test_certificate_validation.c -L../../build -lqtls -loqs -lcrypto
LD_LIBRARY_PATH=../../build ./test_certificate_validation
```

### 3. fuzz_handshake
**핸드셰이크 퍼징 테스트**
- 랜덤 KYBER 암호문 처리
- 랜덤 DILITHIUM 서명 검증
- 랜덤 공유 비밀 키 유도
- 견고성 및 크래시 방지

```bash
gcc -Wall -O2 -I../../include -o fuzz_handshake fuzz_handshake.c \
    -L../../build -lqtls -loqs -lcrypto
LD_LIBRARY_PATH=../../build ./fuzz_handshake
```

## 보안 검증 항목

### 타이밍 공격 방어
- **목표**: 변동계수(CV) < 10%
- **측정**: 1000회 반복 시간 측정
- **통계**: 평균, 표준편차, 변동계수

### 인증서 보안
- ✓ 정상 인증서 검증
- ✓ 위조 서명 거부
- ✓ 변조 감지
- ✓ 만료 확인 (시간 검증)

### 퍼징 견고성
- ✓ 랜덤 입력 처리
- ✓ 크래시 방지
- ✓ 에러 핸들링
- ✓ 메모리 안전성

## 실행 예시

```bash
# 전체 보안 테스트
for test in test_timing test_certificate_validation fuzz_handshake; do
    LD_LIBRARY_PATH=../../build ./$test
done
```

## 보안 권장사항

1. **타이밍 공격**
   - 모든 암호 연산을 상수 시간으로 구현
   - 분기문에서 비밀 데이터 사용 금지
   - 컴파일러 최적화 주의

2. **메모리 보안**
   - 사용 후 즉시 메모리 제로화
   - volatile 키워드로 최적화 방지
   - 스택 오버플로우 방지

3. **인증서 검증**
   - CA 체인 완전 검증
   - 유효 기간 엄격히 확인
   - 폐기 목록(CRL) 확인

4. **랜덤 입력**
   - 모든 입력 검증
   - 버퍼 오버플로우 방지
   - NULL 포인터 체크

## 추가 보안 도구

### Valgrind (메모리 누수)
```bash
valgrind --leak-check=full --show-leak-kinds=all ./test_timing
```

### AddressSanitizer
```bash
gcc -fsanitize=address -g -o test_timing test_timing.c ...
./test_timing
```

### UndefinedBehaviorSanitizer
```bash
gcc -fsanitize=undefined -g -o test_timing test_timing.c ...
./test_timing
```

## 참고 자료

- [NIST PQC 보안 요구사항](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Constant-Time Programming](https://www.bearssl.org/ctmul.html)
- [Certificate Validation Best Practices](https://www.rfc-editor.org/rfc/rfc5280)
