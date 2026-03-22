CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDFLAGS =

TARGET = ledger-engine
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
