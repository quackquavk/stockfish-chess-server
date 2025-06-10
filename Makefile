CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
TARGET = chess_server
SOURCE = stockfish_server.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

install:
	sudo cp $(TARGET) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

.PHONY: clean install uninstall
