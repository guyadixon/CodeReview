CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDFLAGS =

TARGET = sensor-log
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
