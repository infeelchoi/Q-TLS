# Q-TLS 벤치마크 결과

이 디렉토리는 Q-TLS 성능 벤치마크 결과를 저장합니다.

## 벤치마크 실행

벤치마크 도구는 `tools/benchmark/` 디렉토리에 있습니다:

```bash
# 표준 벤치마크 실행
cd ../../tools/benchmark
./benchmark

# HSM 벤치마크 실행 (Luna HSM 필요)
./benchmark_hsm

# 또는 빌드 디렉토리에서
cd ../../build/tools/benchmark
./benchmark
```

## 결과 파일 형식

### CSV 형식

벤치마크 결과는 CSV 형식으로 저장됩니다:

```csv
timestamp,operation,algorithm,iterations,total_time_ms,avg_time_us,ops_per_sec
2024-01-15T10:30:00,keygen,Kyber768,1000,1234.56,1234,809
2024-01-15T10:30:01,encaps,Kyber768,1000,567.89,567,1761
2024-01-15T10:30:02,decaps,Kyber768,1000,789.12,789,1267
```

### JSON 형식

상세 결과는 JSON 형식으로도 저장할 수 있습니다:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "system_info": {
    "cpu": "Intel Xeon E5-2680",
    "cores": 16,
    "memory_gb": 64,
    "os": "Ubuntu 22.04"
  },
  "results": [
    {
      "operation": "keygen",
      "algorithm": "Kyber768",
      "iterations": 1000,
      "total_time_ms": 1234.56,
      "avg_time_us": 1234,
      "min_time_us": 1100,
      "max_time_us": 1500,
      "std_dev_us": 50,
      "ops_per_sec": 809
    }
  ]
}
```

## 벤치마크 항목

### KEM (Kyber) 벤치마크

- **keygen**: 키 쌍 생성
- **encaps**: 캡슐화 (암호화)
- **decaps**: 탈캡슐화 (복호화)

테스트 알고리즘:
- Kyber512
- Kyber768
- Kyber1024

### 서명 (Dilithium) 벤치마크

- **keygen**: 키 쌍 생성
- **sign**: 서명 생성
- **verify**: 서명 검증

테스트 알고리즘:
- Dilithium2
- Dilithium3
- Dilithium5

### TLS 핸드셰이크 벤치마크

- **full_handshake**: 전체 핸드셰이크
- **resume_handshake**: 세션 재개
- **mutual_tls**: 상호 TLS 인증

## 예제 결과

### Kyber768 벤치마크 (Intel Xeon E5-2680)

| 작업 | 평균 시간 | 초당 작업 수 |
|------|----------|-------------|
| 키 생성 | 1.2 ms | 809 ops/s |
| 캡슐화 | 0.6 ms | 1,761 ops/s |
| 탈캡슐화 | 0.8 ms | 1,267 ops/s |

### Dilithium3 벤치마크 (Intel Xeon E5-2680)

| 작업 | 평균 시간 | 초당 작업 수 |
|------|----------|-------------|
| 키 생성 | 2.5 ms | 400 ops/s |
| 서명 | 3.2 ms | 312 ops/s |
| 검증 | 1.8 ms | 555 ops/s |

### TLS 핸드셰이크 벤치마크

| 시나리오 | 평균 시간 | 핸드셰이크/초 |
|---------|----------|--------------|
| 전체 핸드셰이크 (Kyber768 + Dilithium3) | 15.3 ms | 65 hs/s |
| 세션 재개 | 2.1 ms | 476 hs/s |
| 상호 TLS | 18.7 ms | 53 hs/s |

## HSM 벤치마크

Luna HSM을 사용한 경우 별도의 결과 파일에 저장됩니다:

```
benchmark_hsm_YYYYMMDD_HHMMSS.csv
```

일반적으로 HSM은 소프트웨어 구현보다 느리지만 더 높은 보안을 제공합니다.

## 벤치마크 결과 분석

### Python을 사용한 분석

```python
import pandas as pd
import matplotlib.pyplot as plt

# CSV 로드
df = pd.read_csv('benchmark_results.csv')

# 알고리즘별 성능 비교
df.groupby('algorithm')['ops_per_sec'].mean().plot(kind='bar')
plt.title('알고리즘별 평균 성능')
plt.ylabel('초당 작업 수')
plt.savefig('performance_comparison.png')
```

### 시간별 성능 추적

여러 벤치마크 결과를 시간순으로 비교하여 성능 개선을 추적할 수 있습니다.

## 결과 파일 목록

벤치마크 실행 시 다음 파일들이 생성됩니다:

```
benchmark_YYYYMMDD_HHMMSS.csv       # 표준 벤치마크
benchmark_hsm_YYYYMMDD_HHMMSS.csv   # HSM 벤치마크
benchmark_summary.json              # 요약 결과
performance_report.html             # HTML 보고서 (선택적)
```

## 벤치마크 설정

벤치마크 파라미터는 `tools/benchmark/benchmark.c`에서 수정할 수 있습니다:

```c
#define ITERATIONS 1000      // 반복 횟수
#define WARMUP_ROUNDS 100    // 워밍업 라운드
```

## 참고

- 정확한 벤치마크를 위해 시스템 부하가 낮을 때 실행하세요
- 여러 번 실행하여 평균값을 사용하는 것이 좋습니다
- CPU 주파수 스케일링을 비활성화하면 더 일관된 결과를 얻을 수 있습니다

```bash
# CPU 주파수 고정 (Linux)
sudo cpupower frequency-set -g performance
```
