# Q-TLS Go 바인딩

기존 Go 코드와의 원활한 통합을 위해 `net.Conn`을 구현하는 관용적인 Go API를 제공하는 Q-TLS(Quantum-Resistant Transport Security Layer)용 Go 바인딩입니다.

## 기능

- **`net.Conn` 호환**: `crypto/tls`의 드롭인 대체
- **관용적인 Go**: Go 규칙 및 모범 사례 준수
- **Context 지원**: `context.Context` 완벽 지원
- **하이브리드 암호화**: 기존(ECDHE, RSA)과 양자 후(KYBER1024, DILITHIUM3) 알고리즘 결합
- **스레드 안전**: 동시 사용에 안전
- **의존성 없음**: CGo를 사용하여 C 라이브러리와 직접 인터페이스

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

2. Go (>= 1.19) 설치

### Go 바인딩 설치

```bash
go get github.com/QSIGN/Q-TLS/bindings/go
```

또는 로컬에서 사용:
```bash
cd /home/user/QSIGN/Q-TLS/bindings/go
go mod init
go build
```

## 빠른 시작

### 서버 예제

```go
package main

import (
	"fmt"
	"io"
	"log"

	"github.com/QSIGN/Q-TLS/bindings/go/qtls"
)

func main() {
	// Q-TLS 구성
	config := &qtls.Config{
		CertificateFile: "/etc/qtls/server-cert.pem",
		PrivateKeyFile:  "/etc/qtls/server-key.pem",
		HybridMode:      true,
	}

	// 리스너 생성
	listener, err := qtls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Println("Q-TLS 서버가 :8443에서 수신 대기 중")

	// 연결 수락
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("수락 오류:", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 피어 인증서 검증 (Q-TLS 연결용)
	if qtlsConn, ok := conn.(*qtls.Conn); ok {
		if qtlsConn.VerifyPeerCertificate() {
			log.Println("클라이언트 인증서 검증됨")
		}
	}

	// 요청 읽기
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Println("읽기 오류:", err)
		return
	}

	log.Printf("수신: %s", buf[:n])

	// 응답 전송
	response := []byte("Q-TLS 서버에서 안녕하세요!")
	_, err = conn.Write(response)
	if err != nil {
		log.Println("쓰기 오류:", err)
	}
}
```

### 클라이언트 예제

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/QSIGN/Q-TLS/bindings/go/qtls"
)

func main() {
	// Q-TLS 구성
	config := &qtls.Config{
		CAFile:     "/etc/qtls/ca-bundle.pem",
		HybridMode: true,
	}

	// 타임아웃을 사용한 연결
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := qtls.DialContext(ctx, "tcp", "server.example.com:8443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Println("서버에 연결됨")

	// 서버 인증서 검증
	if conn.VerifyPeerCertificate() {
		log.Println("서버 인증서 검증됨!")
	}

	// 요청 전송
	message := []byte("Q-TLS 안녕하세요!")
	_, err = conn.Write(message)
	if err != nil {
		log.Fatal(err)
	}

	// 응답 읽기
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("서버 응답: %s\n", buf[:n])
}
```

## 양자 후 암호화 예제

### KYBER1024 키 캡슐화

```go
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/QSIGN/Q-TLS/bindings/go/qtls"
)

func main() {
	// 서버: 키쌍 생성
	serverKey := qtls.NewKyberKey()
	if err := serverKey.Keygen(); err != nil {
		log.Fatal(err)
	}
	publicKey := serverKey.PublicKey()

	fmt.Println("공개키 크기:", len(publicKey), "바이트")

	// 클라이언트: 캡슐화
	clientKey := qtls.NewKyberKey()
	if err := clientKey.SetPublicKey(publicKey); err != nil {
		log.Fatal(err)
	}

	clientSecret, err := clientKey.Encapsulate()
	if err != nil {
		log.Fatal(err)
	}
	ciphertext := clientKey.Ciphertext()

	// 서버: 역캡슐화
	if err := serverKey.SetCiphertext(ciphertext); err != nil {
		log.Fatal(err)
	}

	serverSecret, err := serverKey.Decapsulate()
	if err != nil {
		log.Fatal(err)
	}

	// 공유 비밀이 일치하는지 확인
	if bytes.Equal(clientSecret, serverSecret) {
		fmt.Println("성공! 공유 비밀이 일치합니다")
	}
}
```

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
