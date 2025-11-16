# Q-TLS Python 바인딩

하이브리드 양자 후 암호화를 지원하는 Q-TLS C 라이브러리에 대한 고급 파이썬 인터페이스를 제공하는 Q-TLS(Quantum-Resistant Transport Security Layer)용 Python 바인딩입니다.

## 기능

- **파이썬 API**: Python 모범 사례를 따르는 깔끔하고 직관적인 인터페이스
- **하이브리드 암호화**: 기존(ECDHE, RSA)과 양자 후(KYBER1024, DILITHIUM3) 알고리즘 결합
- **스레드 안전**: 다중 스레드 애플리케이션에서 안전하게 사용
- **컨텍스트 관리자**: Python의 `with` 문을 사용한 자동 리소스 정리
- **타입 힌트**: IDE 지원 향상을 위한 완전한 타입 주석
- **포괄적인 오류 처리**: 모든 오류 조건에 대한 Python 예외

## 설치

### 전제 조건

1. Q-TLS C 라이브러리 설치:
```bash
cd /home/user/QSIGN/Q-TLS
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
make -j$(nproc)
sudo make install
sudo ldconfig
```

2. Python 의존성 설치:
```bash
pip install -r requirements.txt
```

### Python 바인딩 설치

```bash
cd /home/user/QSIGN/Q-TLS/bindings/python
pip install -e .
```

또는 PyPI에서 설치 (게시된 경우):
```bash
pip install qtls
```

## 빠른 시작

### 서버 예제

```python
from qtls import (
    QTLSContext, QTLSServer,
    QTLS_SERVER_MODE, QTLS_OP_HYBRID_MODE,
    QTLS_VERIFY_PEER
)

# 서버 컨텍스트 생성
ctx = QTLSContext(mode=QTLS_SERVER_MODE)
ctx.use_certificate_file('/etc/qtls/server-cert.pem')
ctx.use_private_key_file('/etc/qtls/server-key.pem')
ctx.set_options(QTLS_OP_HYBRID_MODE)
ctx.set_verify_mode(QTLS_VERIFY_PEER)

# 서버 생성 및 실행
server = QTLSServer(ctx, '0.0.0.0', 8443)
print("Q-TLS 서버가 포트 8443에서 수신 대기 중입니다")

for conn in server.accept_connections():
    try:
        # 요청 읽기
        data = conn.read(4096)
        print(f"수신: {data.decode('utf-8')}")

        # 응답 전송
        response = b'Q-TLS 서버에서 안녕하세요!'
        conn.write(response)

    finally:
        conn.shutdown()
```

### 클라이언트 예제

```python
from qtls import (
    QTLSContext, QTLSClient,
    QTLS_CLIENT_MODE, QTLS_OP_HYBRID_MODE,
    QTLS_VERIFY_PEER, QTLS_VERIFY_FAIL_IF_NO_PEER_CERT
)

# 클라이언트 컨텍스트 생성
ctx = QTLSContext(mode=QTLS_CLIENT_MODE)
ctx.load_verify_locations('/etc/qtls/ca-bundle.pem')
ctx.set_options(QTLS_OP_HYBRID_MODE)
ctx.set_verify_mode(QTLS_VERIFY_PEER | QTLS_VERIFY_FAIL_IF_NO_PEER_CERT)

# 서버에 연결
client = QTLSClient(ctx)
client.connect('server.example.com', 8443)

try:
    # 서버 인증서 검증
    if client.verify_peer_certificate():
        print("서버 인증서 검증됨!")

    # 요청 전송
    client.write(b'Q-TLS 서버 안녕하세요!')

    # 응답 읽기
    response = client.read(4096)
    print(f"서버 응답: {response.decode('utf-8')}")

finally:
    client.shutdown()
```

### 컨텍스트 관리자 사용

```python
from qtls import QTLSContext, QTLSConnection, QTLS_CLIENT_MODE
import socket

ctx = QTLSContext(mode=QTLS_CLIENT_MODE)
ctx.load_verify_locations('/etc/qtls/ca-bundle.pem')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('server.example.com', 8443))

# 컨텍스트 관리자로 자동 정리
with QTLSConnection(ctx, sock) as conn:
    conn.connect()
    conn.write(b'안녕하세요!')
    data = conn.read(4096)
    print(data)
# 여기서 연결이 자동으로 종료됩니다
```

## 양자 후 암호화 예제

### KYBER1024 키 캡슐화

```python
from qtls import QTLSKyber

# 서버 측: 키쌍 생성
server_key = QTLSKyber()
server_key.keygen()
public_key = server_key.get_public_key()

# 클라이언트에 public_key 전송...

# 클라이언트 측: 캡슐화
client_key = QTLSKyber()
client_key.set_public_key(public_key)
client_secret = client_key.encapsulate()
ciphertext = client_key.get_ciphertext()

# 서버에 ciphertext 전송...

# 서버 측: 역캡슐화
server_key.set_ciphertext(ciphertext)
server_secret = server_key.decapsulate()

# 양측이 이제 동일한 공유 비밀을 가집니다
assert client_secret == server_secret
```

### DILITHIUM3 디지털 서명

```python
from qtls import QTLSDilithium

# 키쌍 생성
signing_key = QTLSDilithium()
signing_key.keygen()
public_key = signing_key.get_public_key()

# 메시지 서명
message = b'양자 내성 메시지'
signature = signing_key.sign(message)

# 서명 검증
verify_key = QTLSDilithium()
verify_key.set_public_key(public_key)
is_valid = verify_key.verify(message, signature)
print(f"서명 유효: {is_valid}")
```

## HSM 통합

Q-TLS는 PKCS#11을 통해 하드웨어 보안 모듈(HSM)을 지원합니다:

```python
from qtls import QTLSContext, QTLS_SERVER_MODE

ctx = QTLSContext(mode=QTLS_SERVER_MODE)
ctx.use_certificate_file('/etc/qtls/server-cert.pem')

# Luna HSM에서 개인키 로드
ctx.use_hsm_key('pkcs11:token=luna;object=qtls-server-key;type=private')

# 나머지 서버 설정...
```

## API 참조

### 클래스

#### QTLSContext

Q-TLS 구성을 위한 메인 컨텍스트 클래스입니다.

**메서드:**
- `__init__(mode=QTLS_CLIENT_MODE)` - 새 컨텍스트 생성
- `set_options(options)` - 컨텍스트 옵션 설정
- `set_verify_mode(mode)` - 인증서 검증 모드 설정
- `use_certificate_file(path, file_type=QTLS_FILETYPE_PEM)` - 인증서 로드
- `use_private_key_file(path, file_type=QTLS_FILETYPE_PEM)` - 개인키 로드
- `use_hsm_key(uri)` - HSM에서 키 로드
- `load_verify_locations(ca_file=None, ca_path=None)` - CA 인증서 로드

#### QTLSConnection

저수준 연결 래퍼입니다.

**메서드:**
- `__init__(ctx, sock=None)` - 새 연결 생성
- `connect()` - 클라이언트 핸드셰이크 수행
- `accept()` - 서버 핸드셰이크 수행
- `read(num=4096)` - 암호화된 데이터 읽기
- `write(data)` - 암호화된 데이터 쓰기
- `shutdown()` - 연결 종료
- `verify_peer_certificate()` - 피어 인증서 검증

#### QTLSServer

고수준 서버 클래스입니다.

**메서드:**
- `__init__(ctx, host='0.0.0.0', port=8443)` - 서버 생성
- `accept_connections()` - 들어오는 연결 수락 (제너레이터)
- `close()` - 서버 종료

#### QTLSClient

고수준 클라이언트 클래스입니다.

**메서드:**
- `__init__(ctx)` - 클라이언트 생성
- `connect(host, port=8443)` - 서버에 연결
- `read(num=4096)` - 데이터 읽기
- `write(data)` - 데이터 쓰기
- `shutdown()` - 연결 종료
- `verify_peer_certificate()` - 서버 인증서 검증

#### QTLSKyber

KYBER1024 양자 후 KEM 래퍼입니다.

**메서드:**
- `keygen()` - 키쌍 생성
- `encapsulate()` - 캡슐화 수행 (공유 비밀 반환)
- `decapsulate()` - 역캡슐화 수행 (공유 비밀 반환)
- `get_public_key()` - 공개키 바이트 가져오기
- `set_public_key(key)` - 공개키 설정
- `get_ciphertext()` - 암호문 바이트 가져오기
- `set_ciphertext(ct)` - 암호문 설정

#### QTLSDilithium

DILITHIUM3 양자 후 서명 래퍼입니다.

**메서드:**
- `keygen()` - 키쌍 생성
- `sign(message)` - 메시지 서명 (서명 반환)
- `verify(message, signature)` - 서명 검증 (bool 반환)
- `get_public_key()` - 공개키 바이트 가져오기
- `set_public_key(key)` - 공개키 설정

### 상수

**모드:**
- `QTLS_CLIENT_MODE` - 클라이언트 모드
- `QTLS_SERVER_MODE` - 서버 모드

**옵션:**
- `QTLS_OP_HYBRID_MODE` - 하이브리드 PQC 모드 활성화
- `QTLS_OP_PQC_ONLY` - PQC만 (실험적)
- `QTLS_OP_CLASSICAL_ONLY` - 기존 알고리즘만

**검증:**
- `QTLS_VERIFY_NONE` - 검증 안 함
- `QTLS_VERIFY_PEER` - 피어 인증서 검증
- `QTLS_VERIFY_FAIL_IF_NO_PEER_CERT` - 피어 인증서가 없으면 실패

**파일 타입:**
- `QTLS_FILETYPE_PEM` - PEM 형식
- `QTLS_FILETYPE_ASN1` - ASN.1/DER 형식

### 예외

**QTLSException** - 모든 Q-TLS 오류에 대한 기본 예외

속성:
- `error_code` - 숫자 오류 코드
- C 라이브러리의 오류 메시지

## 스레드 안전성

Q-TLS Python 바인딩은 스레드 안전합니다. 각 `QTLSContext` 및 `QTLSConnection` 객체는 적절한 잠금을 통해 여러 스레드에서 안전하게 사용할 수 있습니다. 그러나 동일한 연결은 동기화 없이 여러 스레드에서 동시에 사용해서는 안 됩니다.

## 성능

Python 바인딩은 C 라이브러리에 대한 최소한의 오버헤드를 추가합니다. 최대 성능을 위해:

1. `read()` 및 `write()`에 더 큰 버퍼 크기 사용
2. 연결 간에 `QTLSContext` 객체 재사용
3. 비동기 애플리케이션을 위해 asyncio 호환 래퍼 사용 고려

## 테스트

테스트 스위트 실행:

```bash
pytest tests/
```

커버리지 포함:

```bash
pytest --cov=qtls tests/
```

## 개발

개발 의존성 설치:

```bash
pip install -e ".[dev]"
```

코드 포매팅:

```bash
black qtls.py
```

타입 검사:

```bash
mypy qtls.py
```

## 문제 해결

### 라이브러리를 찾을 수 없음

"Q-TLS 라이브러리를 로드할 수 없습니다" 오류가 발생하면:

1. Q-TLS C 라이브러리가 설치되어 있는지 확인: `ldconfig -p | grep qtls`
2. `LD_LIBRARY_PATH`에 라이브러리 경로 추가:
   ```bash
   export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
   ```

### 인증서 검증 실패

CA 인증서가 올바르게 설치되어 있는지 확인:
```python
ctx.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
```

### 핸드셰이크 실패

클라이언트와 서버 모두 동일한 PQC 알고리즘을 지원하고 `QTLS_OP_HYBRID_MODE`가 활성화되어 있는지 확인하세요.

## 라이선스

Copyright 2025 QSIGN Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## 지원

- GitHub Issues: https://github.com/QSIGN/Q-TLS/issues
- 문서: https://qtls.readthedocs.io/
- 보안 문제: security@qsign.org

## 감사의 말

- Open Quantum Safe (liboqs) - https://openquantumsafe.org/
- NIST Post-Quantum Cryptography - https://csrc.nist.gov/projects/post-quantum-cryptography
