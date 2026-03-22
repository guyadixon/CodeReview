CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2
LDFLAGS = -lmicrohttpd
TARGET = clinic-api

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
