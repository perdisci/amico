OBJ = pe_dump.o search.o lru-cache.o seq_list.o
CFLAGS = -Wall -O3
CC = gcc
INCLUDE =
LIB = -L /usr/local/lib/ -lpcap -lpthread

pe_dump: ${OBJ}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ ${OBJ} ${LIB}

clean:
	rm -f *.o pe_dump 
