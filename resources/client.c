#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main (int argc, const char* argv[]) {
  char serverName[32];
  char serverPort[5];
  BIO *sbio, *out;
  int len;
  char *message;
  char number[11];
  char tmpbuf[11];
  SSL_CTX *ctx;
  SSL *ssl;
  RSA *privKey;
  FILE *f;
  unsigned int numLength;
  unsigned int sigLength;
  unsigned char *signature;
  
  // check program arguments
  if (argc != 3)
  {
   fprintf(stderr, "Usage: %s <Server Name> <Server Port>\n", argv[0]);
   exit(1);
  }
  strncpy(serverName, argv[1], 32);
  strncpy(serverPort, argv[2], 5);

  // initialize the libraries
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  OpenSSL_add_all_algorithms();

  /* We would seed the PRNG here if the platform didn't
   * do it automatically
   */

  ctx = SSL_CTX_new(SSLv23_client_method());

  /* We'd normally set some stuff like the verify paths and
   * mode here because as things stand this will connect to
   * any server whose certificate is signed by any CA.
   */

  sbio = BIO_new_ssl_connect(ctx);

  BIO_get_ssl(sbio, &ssl);

  if(!ssl) {
   fprintf(stderr, "Can't locate SSL pointer\n");
   /* whatever ... */
  }

  /* Don't want any retries */
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  /* We might want to do other things with ssl here */
   
  // set connection parameters
  BIO_set_conn_hostname(sbio, serverName);
  BIO_set_conn_port(sbio, serverPort);
 
  // create a buffer to print to the screen
  //out = BIO_new_fp(stdout, BIO_NOCLOSE);

  // establish a connection to the server
  printf("Attempting to to connect to the server... ");
  if (BIO_do_connect(sbio) <= 0) {
    fprintf(stderr, "Error connecting to server\n");
    ERR_print_errors_fp(stderr);
    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(ctx);
    exit(1);
  }
  printf("SUCCESS!\n");

  // initiate the handshake with the server
  printf("Initiating SSL handshake with the server... ");
  if (BIO_do_handshake(sbio) <= 0) {
    fprintf(stderr, "Error establishing SSL connection\n");
    ERR_print_errors_fp(stderr);
    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(ctx);
    exit(1);
  }
  printf("SUCCESS!\n");

  // Get the random number from the server
  printf("Waiting for random number from server... ");
  memset(tmpbuf, '\0', 11);
  memset(number, '\0', 11);
  len = BIO_read(sbio, tmpbuf, 10);
  strcpy(number, tmpbuf);
  printf("SUCCESS!\nRandom number is: %s\n", number);
  