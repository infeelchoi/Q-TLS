# Q-TLS 키 생성 도구

양자 내성 암호화 키 쌍(Kyber, Dilithium)을 생성하는 도구입니다.

## 빌드

### 기본 빌드 (liboqs 필요)

```bash
make
```

### HSM 지원 빌드 (Thales Luna HSM)

```bash
make hsm
```

## 사용법

### 1. keygen - 표준 키 생성 도구

#### Kyber KEM 키 생성

```bash
# Kyber512
./keygen -t kem -a Kyber512 -p kyber512_pub.key -s kyber512_sec.key

# Kyber768 (권장)
./keygen -t kem -a Kyber768 -p kyber768_pub.key -s kyber768_sec.key

# Kyber1024
./keygen -t kem -a Kyber1024 -p kyber1024_pub.key -s kyber1024_sec.key
```

#### Dilithium 서명 키 생성

```bash
# Dilithium2
./keygen -t sig -a Dilithium2 -p dilithium2_pub.key -s dilithium2_sec.key

# Dilithium3 (권장)
./keygen -t sig -a Dilithium3 -p dilithium3_pub.key -s dilithium3_sec.key

# Dilithium5
./keygen -t sig -a Dilithium5 -p dilithium5_pub.key -s dilithium5_sec.key
```

#### 지원되는 알고리즘 목록 확인

```bash
./keygen --list
```

### 2. keygen-hsm - HSM 키 생성 도구

#### HSM 슬롯 확인

```bash
./keygen-hsm --list-slots
```

#### HSM에서 Kyber 키 생성

```bash
./keygen-hsm -t kyber -s 0 -p <PIN> -l "my-kyber-key"
```

#### HSM에서 Dilithium 키 생성

```bash
./keygen-hsm -t dilithium -s 0 -p <PIN> -l "my-dilithium-key"
```

## 명령행 옵션

### keygen

```
옵션:
  -t TYPE         키 타입 (kem 또는 sig)
  -a ALGORITHM    알고리즘 이름
  -p PUBLIC_KEY   공개키 출력 파일
  -s SECRET_KEY   비밀키 출력 파일
  -v              상세 출력
  -l, --list      지원되는 알고리즘 목록 표시
  -h, --help      도움말 표시
```

### keygen-hsm

```
옵션:
  -t TYPE         키 타입 (kyber 또는 dilithium)
  -s SLOT_ID      HSM 슬롯 ID
  -p PIN          HSM PIN
  -l LABEL        키 레이블
  -v              상세 출력
  --list-slots    사용 가능한 슬롯 목록 표시
  -h, --help      도움말 표시
```

## 지원 알고리즘

### KEM (Key Encapsulation Mechanism)

| 알고리즘 | 보안 레벨 | 공개키 크기 | 비밀키 크기 | 설명 |
|---------|----------|------------|------------|------|
| Kyber512 | 1 | 800 bytes | 1632 bytes | NIST PQC 표준 |
| Kyber768 | 3 | 1184 bytes | 2400 bytes | **권장** |
| Kyber1024 | 5 | 1568 bytes | 3168 bytes | 최고 보안 |

### 서명 (Digital Signature)

| 알고리즘 | 보안 레벨 | 공개키 크기 | 비밀키 크기 | 서명 크기 | 설명 |
|---------|----------|------------|------------|----------|------|
| Dilithium2 | 2 | 1312 bytes | 2528 bytes | 2420 bytes | NIST PQC 표준 |
| Dilithium3 | 3 | 1952 bytes | 4000 bytes | 3293 bytes | **권장** |
| Dilithium5 | 5 | 2592 bytes | 4864 bytes | 4595 bytes | 최고 보안 |

## 키 관리

### 키 파일 보안

생성된 비밀키는 민감한 정보이므로 안전하게 보관해야 합니다:

```bash
# 비밀키 파일 권한 설정
chmod 600 *_sec.key

# 공개키는 읽기 전용
chmod 644 *_pub.key
```

### 키 백업

```bash
# 암호화된 백업 생성
tar czf keys-backup.tar.gz *.key
gpg -c keys-backup.tar.gz
rm keys-backup.tar.gz

# 복구
gpg -d keys-backup.tar.gz.gpg > keys-backup.tar.gz
tar xzf keys-backup.tar.gz
```

## 테스트

```bash
make test
```

## 시스템 설치

```bash
sudo make install
```

설치 후:
```bash
qtls-keygen -t kem -a Kyber768 -p kyber_pub.key -s kyber_sec.key
qtls-keygen-hsm --list-slots
```

## Q-TLS와 통합

생성된 키는 Q-TLS 라이브러리에서 직접 사용할 수 있습니다:

```c
#include <qtls/qtls.h>

// 키 로드
qtls_key_t *key = qtls_load_key("kyber768_pub.key", "kyber768_sec.key");

// TLS 핸드셰이크에서 사용
qtls_config_set_kem_key(config, key);
```

## 의존성

- **liboqs**: Open Quantum Safe 라이브러리
- **Thales Luna HSM SDK** (선택적): HSM 지원

## 문제 해결

### "알고리즘을 지원하지 않습니다" 오류

liboqs가 올바르게 설치되었는지 확인:
```bash
pkg-config --modversion liboqs
```

### HSM 연결 오류

Luna HSM 클라이언트가 설치되었는지 확인:
```bash
ls /usr/safenet/lunaclient/lib/libCryptoki2_64.so
```

## 참고

- NIST PQC 표준: https://csrc.nist.gov/Projects/post-quantum-cryptography
- liboqs 문서: https://github.com/open-quantum-safe/liboqs
