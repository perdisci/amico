OBJ = file_dump.o search.o lru-cache.o seq_list.o ghash_table.o glru_cache.o fifo_queue.o
CFLAGS = -Wall -O3
CC = gcc
INCLUDE =
LIB = -L /usr/local/lib/ -lpcap -lpthread -lpfring

file_dump: ${OBJ}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ ${OBJ} ${LIB}

clean:
	rm -f *.o file_dump 
