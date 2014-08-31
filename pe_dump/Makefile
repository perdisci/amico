OBJ = pe_dump.o search.o lru-cache.o seq_list.o
CFLAG = -Wall -g
CC = gcc -g -O0
INCLUDE =
LIB = -lpcap -lpthread

pe_dump: ${OBJ}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ ${OBJ} ${LIB}

clean:
	rm -f *.o pe_dump 
