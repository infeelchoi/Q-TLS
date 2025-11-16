# Q-TLS 벤치마크 도구 Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O3 -march=native -I../../include
LDFLAGS = -L../../build -lqtls -loqs -lcrypto -lssl -lpthread -lm

BENCHMARKS = benchmark benchmark_hsm

all: $(BENCHMARKS)

benchmark: benchmark.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

benchmark_hsm: benchmark_hsm.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: benchmark
	@echo "Q-TLS 성능 벤치마크 실행 중..."
	@LD_LIBRARY_PATH=../../build ./benchmark

clean:
	rm -f $(BENCHMARKS) *.o

.PHONY: all run clean
