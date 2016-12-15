/**************************************************************************
 * udptun2.c                                                              *
 *                                                                        *
 * Derived from:                                                          *
 *   http://www.cis.syr.edu/~wedu/seed/Labs/VPN/files/simpletun.c         *
 **************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef unsigned char byte;
const char hn[] = "SHA256";

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555
#define UDP_PORT 4444

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* SSL Certificates and keys */
#define CERTF_C "client.crt"
#define KEYF_C "client.key"
#define CERTF_S "server.crt"
#define KEYF_S "server.key"
#define CACERT "ca.crt"


int debug;
char *progname;

/* udp tunnel */
byte udp_key[32];
byte udp_iv[16];
int udp_negotiation = 1;
int udp_break = 0;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}


/**************************************************************************
 * START evp functions.                                                   *
 **************************************************************************/
// the evp functions are taken from:
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey) {
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !pkey) {
        assert(0);
        return -1;
    }
    
    if(*sig)
        OPENSSL_free(*sig);
    
    *sig = NULL;
    *slen = 0;
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(req > 0);
        if(!(req > 0)) {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        
        assert(req == *slen);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", (long) req, (long) *slen);
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return !!result;
}

int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey) {
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }

    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        byte buff[EVP_MAX_MD_SIZE];
        size_t size = sizeof(buff);
        
        rc = EVP_DigestSignFinal(ctx, buff, &size);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(size > 0);
        if(!(size > 0)) {
            printf("EVP_DigestSignFinal failed (2)\n");
            break; /* failed */
        }
        
        const size_t m = (slen < size ? slen : size);
        result = !!CRYPTO_memcmp(sig, buff, m);
        
        OPENSSL_cleanse(buff, sizeof(buff));
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return !!result;
}
/**************************************************************************
 * END evp functions.                                                     *
 **************************************************************************/


/**************************************************************************
 * ssl_init_client: initiate ssl and returns a (SSL *) reference.         *
 **************************************************************************/
SSL *ssl_init_client(int net_fd) {
  SSL_CTX* ctx; int err; 
  SSL*     ssl;
  X509*    server_cert;
  const SSL_METHOD *meth;
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);   CHK_NULL(ctx);
  CHK_SSL(err); 


  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

  if (SSL_CTX_use_certificate_file(ctx, CERTF_C, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(-2);
  }
  
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF_C, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(-3);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    printf("Private key does not match the certificate public keyn");
    exit(-4);
  }

  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  SSL_set_fd (ssl, net_fd);
  err = SSL_connect (ssl);                     CHK_SSL(err);
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
  printf ("Server certificate:\n");
  char* str;
  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  X509_free (server_cert);

  return ssl;
}

/**************************************************************************
 * ssl_init_server: initiate ssl and returns a (SSL *) reference.         *
 **************************************************************************/
SSL *ssl_init_server(int net_fd) {
  int err;
  SSL_CTX* ctx;
  SSL*     ssl; 
  X509*    client_cert;
  char*    str;
  const SSL_METHOD *meth;
  /* SSL Stuff */

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  
  if (SSL_CTX_use_certificate_file(ctx, CERTF_S, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF_S, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  } 

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  SSL_set_fd (ssl, net_fd);
  err = SSL_accept (ssl);                        CHK_SSL(err);
  
  /* Get the cipher - opt */
  
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get client's certificate (note: beware of dynamic allocation) - opt */

  client_cert = SSL_get_peer_certificate (ssl);
  if (client_cert != NULL) {
    printf ("Client certificate:\n");
    
    str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t subject: %s\n", str);
    OPENSSL_free (str);
    
    str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t issuer: %s\n", str);
    OPENSSL_free (str);
    
    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    
    X509_free (client_cert);
  } else {
    printf ("Client does not have certificate.\n");
    exit(1);
  }

  return ssl;
}

/**************************************************************************
 * udp_loop: handles the udp tunnel.                                      *
 **************************************************************************/
struct udp_loop_args {
  int tap_fd;
  struct sockaddr_in remote;
  SSL *ssl;
};

void *udp_loop(void *args) {
  int tap_fd = ((struct udp_loop_args *) args)->tap_fd;
  struct sockaddr_in remote = ((struct udp_loop_args *) args)->remote;
  SSL *ssl = ((struct udp_loop_args *) args)->ssl;

  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  unsigned long int tap2net = 0, net2tap = 0;
  struct sockaddr_in udp;
  struct sockaddr_in udp_remote;
  int udp_fd;
  struct sockaddr_in frombuf;
  struct sockaddr *from = (struct sockaddr *) &frombuf;
  size_t fromlen = sizeof(frombuf);
  int rc;

  byte ciphertext[BUFSIZE];
  byte plaintext[BUFSIZE];

  const size_t sig_len = 32;
  byte *sig = NULL;
  size_t slen = 0;

  /* init UDP */
  if ((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("UDP: socket()");
    exit(1);
  }

  memset(&udp, 0, sizeof(udp));
  udp.sin_family = AF_INET;
  udp.sin_addr.s_addr = htonl(INADDR_ANY);
  udp.sin_port = htons(UDP_PORT);

  memcpy(&udp_remote, &remote, sizeof(remote));
  udp_remote.sin_port = htons(UDP_PORT);

  if (bind(udp_fd, (struct sockaddr *) &udp, sizeof(udp)) < 0){
    perror("UDP: bind()");
    exit(1);
  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > udp_fd)?tap_fd:udp_fd;

  while(!udp_break) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(udp_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set) && !udp_negotiation){
      /* data from tun/tap: just read it and write it to the network */

      tap2net++;

      nread = cread(tap_fd, buffer, BUFSIZE);
      plength = nread;
      do_debug("TAP2UDP %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* sign */
      sign_it(buffer, plength, &sig, &slen, EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, udp_key, sizeof(udp_key)));
      assert(slen==sig_len);
      memcpy(buffer+plength, sig, sig_len);
      /* encrypt */
      rc = encrypt(buffer, plength+sig_len, udp_key, udp_iv, ciphertext);

      /* send packet */
      nwrite = sendto(udp_fd, ciphertext, rc, 0, (struct sockaddr *) &udp_remote, sizeof(struct sockaddr));
      do_debug("TAP2UDP %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(udp_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      net2tap++;

      /* read packet */
      nread = recvfrom(udp_fd, buffer, BUFSIZE, MSG_DONTWAIT, from, &fromlen);
      do_debug("UDP2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* decrypt */
      rc = decrypt(buffer, nread, udp_key, udp_iv, plaintext);
      plength = rc-sig_len;
      /* verify */
      verify_it(plaintext, plength, plaintext+plength, sig_len, EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, udp_key, sizeof(udp_key)));

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, plaintext, plength);
      do_debug("UDP2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }

  close(udp_fd);
  printf("udp_loop: good bye!\n");
}

/**************************************************************************
 * ctrl_loop: handles the ctrl loop.                                      *
 **************************************************************************/
struct ctrl_loop_args {
  int ctrl_fd_r;
  int net_fd;
  SSL *ssl;
};

void *ctrl_loop_client(void *args) {
  int ctrl_fd_r = ((struct ctrl_loop_args *) args)->ctrl_fd_r;
  int net_fd = ((struct ctrl_loop_args *) args)->net_fd;
  SSL *ssl = ((struct ctrl_loop_args *) args)->ssl;

  char buffer[BUFSIZE];
  char buffer2[BUFSIZE];
  int maxfd;
  uint16_t nread, nwrite, plength, buffer_len, buffer2_len;
  unsigned long int cmd2net = 0, net2cmd = 0;
  int rc;
  char outbuf[BUFSIZE];
  int i;

  BIO *for_reading = BIO_new(BIO_s_mem());
  BIO *for_writing = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(for_reading, -1);
  BIO_set_mem_eof_return(for_writing, -1);
  SSL_set_bio(ssl, for_reading, for_writing);

  // 'a'+[initial key]+[initial iv]
  buffer2[0] = 'a';
  buffer2_len = 1;
  RAND_bytes(udp_key, sizeof(udp_key));
  for (i=0; i<sizeof(udp_key); i++) {
    buffer2[buffer2_len++] = udp_key[i];
  }
  RAND_bytes(udp_iv, sizeof(udp_iv));
  for (i=0; i<sizeof(udp_iv); i++) {
    buffer2[buffer2_len++] = udp_iv[i];
  }
  rc = SSL_write(ssl, buffer2, buffer2_len);
  rc = BIO_read(for_writing, outbuf, sizeof(outbuf));
  nwrite = send(net_fd, outbuf, rc, 0);
  do_debug("CMD2TCP %lu: Written %d bytes to the network\n", cmd2net, nwrite);

  maxfd = (ctrl_fd_r > net_fd)?ctrl_fd_r:net_fd;
  
  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(ctrl_fd_r, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd+1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if (FD_ISSET(ctrl_fd_r, &rd_set)) {
      /* data from cmd prompt */

      cmd2net++;

      nread = cread(ctrl_fd_r, buffer, BUFSIZE);
      buffer[nread] = '\0';
      do_debug("CMD2TCP %lu: Read %d bytes from the cmd prompt\n", cmd2net, nread);

      do {
        if (strcmp(buffer, "change key\n") == 0) {
          do_debug("from cmd: change key\n");
          udp_negotiation=1;
          buffer2[0] = 'k';
          buffer2_len = 1;

          // 'k'+[new key]
          RAND_bytes(udp_key, sizeof(udp_key));
          for (i=0; i<sizeof(udp_key); i++) {
            buffer2[buffer2_len++] = udp_key[i];
          }

        } else if (strcmp(buffer, "change iv\n") == 0) {
          do_debug("from cmd: change iv\n");
          udp_negotiation=1;
          buffer2[0] = 'i';
          buffer2_len = 1;

          // 'i'+[new iv]
          RAND_bytes(udp_iv, sizeof(udp_iv));
          for (i=0; i<sizeof(udp_iv); i++) {
            buffer2[buffer2_len++] = udp_iv[i];
          }

        } else if(strcmp(buffer, "break tunnel\n") == 0) {
          do_debug("from cmd: break tunnel\n");
          udp_break=1;
          buffer2[0] = 'b';
          buffer2_len = 1;

        } else if(strcmp(buffer, "show secrets\n") == 0) {
          printf("udp tunnel key: ");
          for (i=0; i<sizeof(udp_key); i++) {
            printf("%x", udp_key[i]);
          }
          printf("\nudp tunnel iv: ");
          for (i=0; i<sizeof(udp_iv); i++) {
            printf("%x", udp_iv[i]);
          }
          printf("\n");
          break;
        } else {
          printf("from cmd: invalid command!\n");
          break;
        }

        /* call OpenSSL to write out our buffer of data. */
        /* reminder: this actually writes it out to a memory bio */
        rc = SSL_write(ssl, buffer2, buffer2_len);
        /* Read the actual packet to be sent out of the for_writing bio */
        rc = BIO_read(for_writing, outbuf, sizeof(outbuf));

        nwrite = send(net_fd, outbuf, rc, 0);
        do_debug("CMD2TCP %lu: Written %d bytes to the network\n", cmd2net, nwrite);
      } while(0);
    }

    if (FD_ISSET(net_fd, &rd_set)) {
      /* data from the network */

      net2cmd++;

      nread = recv(net_fd, buffer, BUFSIZE, MSG_DONTWAIT);
      do_debug("TCP2CMD %lu: Read %d bytes from the network\n", net2cmd, nread);

      /* write the received buffer from the UDP socket to the memory-based input bio */
      rc = BIO_write(for_reading, buffer, nread);
      /* Tell openssl to process the packet now stored in the memory bio */
      rc = SSL_read(ssl, buffer, BUFSIZE);
      /* at this point buf will store the results (with a length of rc) */
      do_debug("TCP2CMD %lu: Written %d bytes to the buffer\n", net2cmd, rc);

      if (buffer[0] == 'b') {
        printf("from server: ACCEPT initial key and iv\n");
        udp_negotiation=0;
      }
      else if (buffer[0] == 'l') {
        printf("from server: ACCEPT change key\n");
        udp_negotiation=0;
      } else if (buffer[0] == 'j') {
        printf("from server: ACCEPT change iv\n");
        udp_negotiation=0;
      } else {
        printf("from server: invalid command!\n");
        break;
      }
    }
  }
}

void *ctrl_loop_server(void *args) {
  int ctrl_fd_r = ((struct ctrl_loop_args *) args)->ctrl_fd_r;
  int net_fd = ((struct ctrl_loop_args *) args)->net_fd;
  SSL *ssl = ((struct ctrl_loop_args *) args)->ssl;

  char buffer[BUFSIZE];
  char buffer2[BUFSIZE];
  int maxfd;
  uint16_t nread, nwrite, plength, buffer_len, buffer2_len;
  unsigned long int cmd2net = 0, net2cmd = 0;
  int rc;
  char outbuf[BUFSIZE];
  int i;

  BIO *for_reading = BIO_new(BIO_s_mem());
  BIO *for_writing = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(for_reading, -1);
  BIO_set_mem_eof_return(for_writing, -1);
  SSL_set_bio(ssl, for_reading, for_writing);

  maxfd = (ctrl_fd_r > net_fd)?ctrl_fd_r:net_fd;
  
  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(ctrl_fd_r, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd+1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if (FD_ISSET(net_fd, &rd_set)) {
      /* data from the network */

      net2cmd++;

      nread = recv(net_fd, buffer, BUFSIZE, MSG_DONTWAIT);
      do_debug("TCP2CMD %lu: Read %d bytes from the network\n", net2cmd, nread);

      /* write the received buffer from the UDP socket to the memory-based input bio */
      rc = BIO_write(for_reading, buffer, nread);
      /* Tell openssl to process the packet now stored in the memory bio */
      rc = SSL_read(ssl, buffer, BUFSIZE);
      /* at this point buf will store the results (with a length of rc) */
      do_debug("TCP2CMD %lu: Written %d bytes to the buffer\n", net2cmd, rc);

      if (buffer[0] == 'a') {
        printf("from client: initial key and iv\n");
        for (i=0; i<sizeof(udp_key); i++) {
          udp_key[i] = buffer[i+1];
        }
        for (i=0; i<sizeof(udp_iv); i++) {
          udp_iv[i] = buffer[i+1+sizeof(udp_key)];
        }

        udp_negotiation = 0;

        buffer[0] = 'b';
        rc = SSL_write(ssl, buffer, 1);
        rc = BIO_read(for_writing, outbuf, sizeof(outbuf));
        nwrite = send(net_fd, outbuf, rc, 0);
        do_debug("TCP2CMD %lu: Written %d bytes to the network\n", net2cmd, nwrite);
      }
      else if (buffer[0] == 'k') {
        printf("from client: change key\n");
        for (i=0; i<sizeof(udp_key); i++) {
          udp_key[i] = buffer[i+1];
        }

        buffer[0] = 'l';
        rc = SSL_write(ssl, buffer, 1);
        rc = BIO_read(for_writing, outbuf, sizeof(outbuf));
        nwrite = send(net_fd, outbuf, rc, 0);
        do_debug("TCP2CMD %lu: Written %d bytes to the network\n", cmd2net, nwrite); 

      } else if (buffer[0] == 'i') {
        printf("from client: change iv\n");
        for (i=0; i<sizeof(udp_iv); i++) {
          udp_iv[i] = buffer[i+1];
        }

        buffer[0] = 'j';
        rc = SSL_write(ssl, buffer, 1);
        rc = BIO_read(for_writing, outbuf, sizeof(outbuf));
        nwrite = send(net_fd, outbuf, rc, 0);
        do_debug("TCP2CMD %lu: Written %d bytes to the network\n", cmd2net, nwrite); 


      } else if(buffer[0] == 'b') {
        printf("from client: break tunnel\n");
        udp_break=1;

      } else {
        printf("from client: invalid command!\n");
        break;
      }
    }
  }
}


int main(int argc, char *argv[]) {  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
//  uint16_t total_len, ethertype;
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  struct udp_loop_args udp_loop_args;
  struct ctrl_loop_args ctrl_loop_args;
  pthread_t udp_thread;
  pthread_t ctrl_thread;
  char *line;
  ssize_t bufsize = 0;
  SSL *ssl;
  char *ctrl_pipe;
  int ctrl_fd_r;
  int ctrl_fd_w;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  if(cliserv==CLIENT){
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    if (connect(sock_fd, (struct sockaddr *) &remote, sizeof(remote)) < 0){
      perror("connect()");
      exit(1);
    }

    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));

    ssl = ssl_init_client(net_fd);
    
  } else {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr *) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    
    if (listen(sock_fd, 5) < 0){
      perror("listen()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((net_fd = accept(sock_fd, (struct sockaddr *) &remote, &remotelen)) < 0){
      perror("accept()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));

    ssl = ssl_init_server(net_fd);
  }

  /* udp */
  udp_loop_args.tap_fd = tap_fd;
  udp_loop_args.remote = remote;
  udp_loop_args.ssl = ssl;
  pthread_create(&udp_thread, NULL, udp_loop, (void *) &udp_loop_args);

  /* ctrl */
  ctrl_pipe = strdup("/tmp/ctrlpipe");
  mkfifo(ctrl_pipe, 0666);
  ctrl_fd_r = open(ctrl_pipe, O_RDONLY|O_NONBLOCK);
  ctrl_fd_w = open(ctrl_pipe, O_WRONLY|O_NONBLOCK);
  ctrl_loop_args.ctrl_fd_r = ctrl_fd_r;
  ctrl_loop_args.net_fd = net_fd;
  ctrl_loop_args.ssl = ssl;
  if (cliserv==CLIENT) {
    pthread_create(&ctrl_thread, NULL, &ctrl_loop_client, (void *) &ctrl_loop_args);
  } else {
    pthread_create(&ctrl_thread, NULL, &ctrl_loop_server, (void *) &ctrl_loop_args);
  }

  /* cmd prompt */
  do {
    printf("> ");
    int line_len = getline(&line, &bufsize, stdin);
    if (cliserv==CLIENT) {
      cwrite(ctrl_fd_w, line, line_len);
    }
  } while (strcmp(line, "exit\n") != 0);

  return(0);
}
