INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:	
	gcc -I$(INC) -L$(LIB) udptun2.c -o udptun2 -lssl -lcrypto -ldl -pthread
