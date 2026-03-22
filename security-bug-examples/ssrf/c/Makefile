CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lmicrohttpd -lcurl

TARGET = gateway-server
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
