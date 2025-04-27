CC = gcc
CFLAGS = -g -Wall -std=c99

crack: crack.o password.o md5.o block.o magic.o

crack.o: crack.c

unitTest: unitTest.o password.o md5.o block.o magic.o

unitTest.o: unitTest.c

password.o: md5.o password.h password.c

md5.o: block.o md5.h md5.c

block.o: magic.o block.h block.c

magic.o: magic.h magic.c

clean:
	rm -f *.o
	rm -f crack
	rm -f unitTest
