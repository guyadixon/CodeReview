CC = gcc
CFLAGS = -Wall -Wextra -std=c11 $(shell pkg-config --cflags libmicrohttpd libxml-2.0)
LDFLAGS = $(shell pkg-config --libs libmicrohttpd libxml-2.0)

TARGET = config_api
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
