/**************************************************************************
 * udptun.c                                                               *
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

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
  char outbuf[BUFSIZE];
  unsigned long int tap2net = 0, net2tap = 0;
  struct sockaddr_in udp;
  struct sockaddr_in udp_remote;
  int udp_fd;
  struct sockaddr_in frombuf;
  struct sockaddr *from = (struct sockaddr *) &frombuf;
  size_t fromlen = sizeof(frombuf);
  int rc;

  BIO *for_reading = BIO_new(BIO_s_mem());
  BIO *for_writing = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(for_reading, -1);
  BIO_set_mem_eof_return(for_writing, -1);
  SSL_set_bio(ssl, for_reading, for_writing);

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

  while(1) {
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

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */

      tap2net++;

      nread = cread(tap_fd, buffer, BUFSIZE);
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* call OpenSSL to write out our buffer of data. */
      /* reminder: this actually writes it out to a memory bio */
      rc = SSL_write(ssl, buffer, nread);
      do_debug("TAP2NET %lu: SSL_write(): %d\n", tap2net, rc);
      /* Read the actual packet to be sent out of the for_writing bio */
      rc = BIO_read(for_writing, outbuf, sizeof(outbuf));
      do_debug("TAP2NET %lu: BIO_read(): %d\n", tap2net, rc);

      /* send packet */
      nwrite = sendto(udp_fd, outbuf, rc, 0, (struct sockaddr *) &udp_remote, sizeof(struct sockaddr));
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(udp_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      net2tap++;

      /* read packet */
      nread = recvfrom(udp_fd, buffer, BUFSIZE, MSG_DONTWAIT, from, &fromlen);
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* write the received buffer from the UDP socket to the memory-based input bio */
      rc = BIO_write(for_reading, buffer, nread);
      do_debug("NET2TAP %lu: BIO_write(): %d\n", tap2net, rc);
      /* Tell openssl to process the packet now stored in the memory bio */
      rc = SSL_read(ssl, buffer, BUFSIZE);
      do_debug("NET2TAP %lu: SSL_read(): %d\n", tap2net, rc);
      /* at this point buf will store the results (with a length of rc) */

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, rc);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
}

/**************************************************************************
 * ctrl_loop: handles the ctrl loop.                                      *
 **************************************************************************/
struct ctrl_loop_args {
  int ctrl_fd_r;
  int net_fd;
  SSL *ssl;
};

void *ctrl_loop(void *args) {
  int ctrl_fd_r = ((struct ctrl_loop_args *) args)->ctrl_fd_r;
  int net_fd = ((struct ctrl_loop_args *) args)->net_fd;
  SSL *ssl = ((struct ctrl_loop_args *) args)->ssl;

  char buffer[BUFSIZE];
  int maxfd;
  uint16_t nread, nwrite, plength;

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
      cread(ctrl_fd_r, buffer, BUFSIZE);
      cwrite(net_fd, buffer, BUFSIZE);
    }

    if (FD_ISSET(net_fd, &rd_set)) {
      read_n(net_fd, buffer, BUFSIZE);
      printf("incoming msg: %s", buffer);
    }
  }
}

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
  char ctrl_pipe[] = "/tmp/ctrlpipe";
  mkfifo(ctrl_pipe, 0666);
  int ctrl_fd_r = open(ctrl_pipe, O_RDONLY|O_NONBLOCK);
  int ctrl_fd_w = open(ctrl_pipe, O_WRONLY|O_NONBLOCK);
  ctrl_loop_args.ctrl_fd_r = ctrl_fd_r;
  ctrl_loop_args.net_fd = net_fd;
  ctrl_loop_args.ssl = ssl;
  pthread_create( &ctrl_thread, NULL, &ctrl_loop, (void *) &ctrl_loop_args);

  /* cmd prompt */
  do {
    printf("> ");
    int line_len = getline(&line, &bufsize, stdin);
    cwrite(ctrl_fd_w, line, line_len);
  } while (strcmp(line, "exit\n") != 0);

  return(0);
}
