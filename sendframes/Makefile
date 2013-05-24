CMP= clang
CMPFLAGS=	-g -Wall -Werror -W -O0 -pedantic -std=c89 
LDFLAGS= -lrt
EXENAME=
LIBNAME=	

compile: sendframes

sendframes: sendframes.c
		$(CMP) $(LDFLAGS) $(CMPFLAGS) sendframes.c -o sendframes

clean:
		rm -f *.o

all:		
		make
