OBJ = ht_test.o ../../ghash_table.o
CFLAGS = -Wall -g -O0
CC = gcc
INCLUDE =
LIB = 

ht_test: ${OBJ}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ ${OBJ} ${LIB}

clean:
	rm -f *.o ht_test
