CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
TARGET = inventory-api

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) main.cpp

clean:
	rm -f $(TARGET)

.PHONY: all clean
