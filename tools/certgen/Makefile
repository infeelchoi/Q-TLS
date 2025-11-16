# Q-TLS 인증서 생성 도구 Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGET = certgen
SOURCES = certgen.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJECTS)
	rm -f *.pem *.csr *.srl *.cnf

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	install -m 755 generate-ca.sh /usr/local/bin/qtls-gen-ca
	install -m 755 generate-server.sh /usr/local/bin/qtls-gen-server
	install -m 755 generate-client.sh /usr/local/bin/qtls-gen-client

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	rm -f /usr/local/bin/qtls-gen-ca
	rm -f /usr/local/bin/qtls-gen-server
	rm -f /usr/local/bin/qtls-gen-client
