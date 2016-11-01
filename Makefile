all: openssl

openssl:
	gcc -o server tls_server_openssl.c -lssl -lcrypto
	gcc -o client tls_client_openssl.c -lssl -lcrypto

polarssl:
	gcc -o server ssl_server_polarssl.c -lpolarssl -L../lib -I../include
	gcc -o client ssl_client_polarssl.c -lpolarssl -L../lib -I../include

clean:
	rm -rf server client
