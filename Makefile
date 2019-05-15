.PHONY: all clean
all: server client

server: server.cpp
	g++ server.cpp -o server -luv -O3

client: client.cpp
	g++ client.cpp -o client -luv -O3

clean:
	rm server client
