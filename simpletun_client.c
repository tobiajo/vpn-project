/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

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

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

/* SSL Certificates and keys */
#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

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

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
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
  fprintf(stderr, "%s -i <ifacename> [-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-c <serverIP>: specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
//  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:c:p:uahd")) > 0){
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

/* SSL stuff */

  SSL_CTX* ctx; int err; 
  SSL*     ssl;
  X509*    server_cert;
  SSL_METHOD *meth;
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);   CHK_NULL(ctx);
  CHK_SSL(err); 


  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
	  ERR_print_errors_fp(stderr);
	  exit(-2);
  }
  
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
	  ERR_print_errors_fp(stderr);
	  exit(-3);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
	  printf("Private key does not match the certificate public keyn");
	  exit(-4);
  }

 progname = argv[0];

 /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
 


  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

/* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
      perror("connect()");
      exit(1);
    }
/* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */

  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  SSL_set_fd (ssl, sock_fd);
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

  do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    

  net_fd = sock_fd;
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

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
      
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* write length + packet */
      plength = htons(nread);
      // write to network using SSL
      err = SSL_write (ssl, (char *)&plength, sizeof(plength));  CHK_SSL(err);
      err = SSL_write (ssl, buffer, nread);  CHK_SSL(err);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, err);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */           
      err = SSL_read (ssl, (char *)&plength, sizeof(plength));   CHK_SSL(err);
      if( err == 0) {
        /* ctrl-c at the other end */
        do_debug("SSL_read returned zero\n");
        break;
      }

      net2tap++;
      do_debug("NET2TAP %lu: Attempting to read %d bytes from the network\n", net2tap, plength);

      /* read packet */
      err = SSL_read (ssl, buffer, ntohs(plength));   CHK_SSL(err);     
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, err);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, err);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}

