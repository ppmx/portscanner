CC=clang

all:
	mkdir -p build/
	$(CC) -Wall -Wextra ./src/syn_scanner.c -o ./build/syn_scanner

clean:
	rm -rf build/*
