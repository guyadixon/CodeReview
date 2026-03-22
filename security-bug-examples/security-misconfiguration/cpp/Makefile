CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -pthread $(shell pkg-config --cflags libxml-2.0)
LDFLAGS = -pthread $(shell pkg-config --libs libxml-2.0)

TARGET = config_api
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
