# Q-TLS Node.js 바인딩

하이브리드 양자 후 암호화를 위한 Promise 기반 비동기 API와 EventEmitter 지원을 제공하는 Q-TLS(Quantum-Resistant Transport Security Layer)용 Node.js 바인딩입니다.

## 기능

- **Promise 기반 API**: 최신 async/await 인터페이스
- **EventEmitter**: 연결을 위한 이벤트 기반 아키텍처
- **하이브리드 암호화**: 기존(ECDHE, RSA)과 양자 후(KYBER1024, DILITHIUM3) 알고리즘 결합
- **네이티브 성능**: 최대 성능을 위한 N-API를 사용하는 네이티브 C++ 애드온
- **TypeScript 지원**: 완전한 TypeScript 정의 포함
- **스트림 호환**: Node.js 스트림과 함께 작동

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

2. Node.js (>= 14.0.0) 및 npm 설치

### Node.js 바인딩 설치

```bash
cd /home/user/QSIGN/Q-TLS/bindings/nodejs
npm install
```

또는 npm에서 설치 (게시된 경우):
```bash
npm install qtls
```

## 빠른 시작

### 서버 예제

```javascript
const { QTLSServer, QTLS_SERVER_MODE, QTLS_OP_HYBRID_MODE } = require('qtls');

// 서버 생성
const server = new QTLSServer({
  mode: QTLS_SERVER_MODE,
  cert: '/etc/qtls/server-cert.pem',
  key: '/etc/qtls/server-key.pem',
  hybrid: true
});

// 연결 수신 대기
server.on('connection', async (conn) => {
  console.log('새 연결이 설정되었습니다');

  try {
    // 데이터 읽기
    const data = await conn.read();
    console.log('수신:', data.toString());

    // 응답 전송
    await conn.write('Q-TLS 서버에서 안녕하세요!');
  } catch (err) {
    console.error('오류:', err);
  } finally {
    await conn.close();
  }
});

server.on('error', (err) => {
  console.error('서버 오류:', err);
});

// 수신 대기 시작
server.listen(8443, '0.0.0.0', () => {
  console.log('Q-TLS 서버가 포트 8443에서 수신 대기 중입니다');
});
```

### 클라이언트 예제

```javascript
const { QTLSClient, QTLS_CLIENT_MODE, QTLS_VERIFY_PEER } = require('qtls');

async function main() {
  // 클라이언트 생성
  const client = new QTLSClient({
    mode: QTLS_CLIENT_MODE,
    ca: '/etc/qtls/ca-bundle.pem',
    hybrid: true,
    verify: QTLS_VERIFY_PEER
  });

  try {
    // 서버에 연결
    await client.connect('server.example.com', 8443);
    console.log('서버에 연결됨');

    // 인증서 검증
    if (client.verifyPeerCertificate()) {
      console.log('서버 인증서 검증됨!');
    }

    // 데이터 전송
    await client.write('Q-TLS 서버 안녕하세요!');

    // 응답 수신
    const response = await client.read();
    console.log('서버 응답:', response.toString());

  } catch (err) {
    console.error('오류:', err);
  } finally {
    await client.close();
  }
}

main().catch(console.error);
```

## 양자 후 암호화 예제

### KYBER1024 키 캡슐화

```javascript
const { QTLSKyber } = require('qtls');

async function kyberExample() {
  // 서버: 키쌍 생성
  const serverKey = new QTLSKyber();
  await serverKey.keygen();
  const publicKey = serverKey.getPublicKey();

  // 클라이언트: 캡슐화
  const clientKey = new QTLSKyber();
  clientKey.setPublicKey(publicKey);
  const clientSecret = await clientKey.encapsulate();
  const ciphertext = clientKey.getCiphertext();

  // 서버: 역캡슐화
  serverKey.setCiphertext(ciphertext);
  const serverSecret = await serverKey.decapsulate();

  // 양측이 동일한 공유 비밀을 가집니다
  console.log('비밀이 일치함:',
    clientSecret.equals(serverSecret));
}

kyberExample().catch(console.error);
```

### DILITHIUM3 디지털 서명

```javascript
const { QTLSDilithium } = require('qtls');

async function dilithiumExample() {
  // 키쌍 생성
  const signingKey = new QTLSDilithium();
  await signingKey.keygen();
  const publicKey = signingKey.getPublicKey();

  // 메시지 서명
  const message = Buffer.from('양자 내성 메시지');
  const signature = await signingKey.sign(message);

  console.log('서명 크기:', signature.length, '바이트');

  // 서명 검증
  const verifyKey = new QTLSDilithium();
  verifyKey.setPublicKey(publicKey);
  const isValid = await verifyKey.verify(message, signature);

  console.log('서명 유효:', isValid);
}

dilithiumExample().catch(console.error);
```

## API 참조

### 클래스

#### QTLSServer

고수준 서버(EventEmitter 확장).

**이벤트:**
- `listening` - 서버가 수신 대기 시작
- `connection` - 새 연결 수락됨
- `error` - 오류 발생

**메서드:**
- `listen(port, host?, callback?)` - 수신 대기 시작
- `close(callback?)` - 서버 종료

#### QTLSClient

고수준 클라이언트(EventEmitter 확장).

**이벤트:**
- `connect` - 서버에 연결됨
- `data` - 데이터 수신됨
- `close` - 연결 종료됨
- `error` - 오류 발생

**메서드:**
- `connect(host, port?)` - 서버에 연결 (Promise 반환)
- `read(size?)` - 데이터 읽기 (Promise<Buffer> 반환)
- `write(data)` - 데이터 쓰기 (Promise<number> 반환)
- `close()` - 연결 종료 (Promise 반환)
- `verifyPeerCertificate()` - 서버 인증서 검증 (boolean 반환)

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
