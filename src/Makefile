CFLAGS = -Wall -g
SRC = main.c litecoin.c SHA256.c
OBJ = ${SRC:.c=.o}
TARGET = litecoin

all: ${TARGET}

.c.o:
	g++ -std=c++11 -c ${CFLAGS} $<

${TARGET}: ${OBJ}
	g++ -std=c++11 -o $@ ${OBJ} -lcrypto -lssl

clean:
	@rm -f ${TARGET} ${OBJ}
