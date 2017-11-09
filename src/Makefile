CFLAGS = -Wall -g
SRC = main.c litecoin.c SHA256.c
OBJ = ${SRC:.c=.o}
TARGET = litecoin
BIN = test

all: ${TARGET}

.c.o:
	g++ -std=c++11 -c ${CFLAGS} $<

${TARGET}: ${OBJ}
	g++ -std=c++11 -o $@ ${OBJ} -lcrypto -lssl

run: $(BIN)
	./$(BIN)

$(BIN): testmagic.o
	gcc testmagic.o -o $(BIN)

testmagic.o: testmagic.c
	gcc -c testmagic.c -o testmagic.o

clean:
	@rm -f ${TARGET} ${OBJ}

