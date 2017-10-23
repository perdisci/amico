OBJ = glruc_test.o ../../ghash_table.o ../../glru_cache.o
CFLAGS = -Wall -g -O0
CC = gcc
INCLUDE =
LIB = 

glruc_test: ${OBJ}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ ${OBJ} ${LIB}

clean:
	rm -f *.o ../../*.o glruc_test
