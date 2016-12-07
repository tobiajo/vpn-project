INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:	
#	g++ -I$(INC) -L$(LIB) simpletun_client.c -o simpletun_client -lssl -lcrypto -ldl -fpermissive
#	g++ -I$(INC) -L$(LIB) simpletun_server.c -o simpletun_server -lssl -lcrypto -ldl -fpermissive
	gcc -I$(INC) -L$(LIB) udptun.c -o udptun -lssl -lcrypto -ldl -pthread

#clean:
#	rm -rf *~ simpletun_client simpletun_server udptun
