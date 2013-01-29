CC=g++
CFLAGS=-Wall
LDFLAGS=-lcrypto -lpolarssl
SOURCES=lib/kgen.cpp lib/aes_xts.cpp lib/util.cpp lib/keys.cpp lib/indiv.cpp lib/eid.cpp lib/hdd.cpp lib/main.cpp
EXECUTABLE=decrypt_tools
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)
