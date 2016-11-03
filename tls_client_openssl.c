#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"

static void showCerts(SSL* ssl)
{
  X509* cert;
  char* line;

  printf("Encryption %s\n", SSL_get_cipher(ssl));
  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    printf("Peer certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    sk_X509_free(cert);
  }
  else
    printf("No certificates.\n");
}

static int clientContextInit(SSL_CTX** ssl_ctx /* output */)
{
  int ret = 0;
  SSL_CTX* ctx;

  /* define TLS method */

  ctx = SSL_CTX_new(TLSv1_2_client_method());

  if (ctx == NULL) {
    ret = -EPERM;
  }

  if (!ret &&
      SSL_CTX_set_ecdh_auto(ctx, 1) != 1)
  {
    ret = -EFAULT;
  }

  /* load certificate */

  if (!ret &&
      SSL_CTX_use_certificate_file(ctx,
                                   TLS_CLIENT_CERT,
                                   SSL_FILETYPE_PEM) <= 0)
  {
    ret = -EPERM;
  }

  if (!ret &&
      SSL_CTX_use_PrivateKey_file(ctx,
                                  TLS_CLIENT_KEY,
                                  SSL_FILETYPE_PEM) <= 0)
  {
    ret = -EPERM;
  }

  /* load private key */

  if (!ret &&
      SSL_CTX_check_private_key(ctx) != 1)
  {
    printf("Private key does not match the certificate\n");
    ret = -EACCES;
  }

  if (!ret &&
      SSL_CTX_load_verify_locations(ctx, TLS_CA_CERT, NULL) != 1)
  {
    ret = -EPERM;
  }

  if (!ret)
  {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL /* TODO: callback */);
    SSL_CTX_set_verify_depth(ctx, 1);
  }

  if (ret)
  {
    /* show error description */
    ERR_print_errors_fp(stderr);

    if (ctx)
      SSL_CTX_free(ctx);
  }
  else
  {
    /* assign the output value */
    *ssl_ctx = ctx;
  }

  return ret;
}

static int clientContextUp(SSL_CTX** ssl_ctx /* output */)
{
  int ret = 0;

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ret = clientContextInit(ssl_ctx);

  return ret;
}

static int clientSocketUp(int* sockfd /* output */)
{
  int ret = 0;
  int fd;
  struct hostent* host;
  struct sockaddr_in addr;

  if (!ret)
  {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
      perror("socket");
      ret = -EPERM;
    }
  }

  if (!ret)
  {
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TLS_SERVER_LISTEN_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    /*
    strncpy(&(addr.sun_path[1]),
            TLS_SERVER_ADDR,
            strlen(TLS_SERVER_ADDR) + 1);
    */

    ret = connect(fd, (struct sockaddr*) &addr, sizeof(addr));

    if (ret < 0)
    {
      perror("connect");
      ret = -errno;
    }
  }

  if (!ret)
    /* assign the output value */
    *sockfd = fd;
  else if (fd >= 0)
    close(fd);

  return ret;
}

static int clientSslUp(SSL_CTX* ssl_ctx /* input */,
                       int sockfd /* input */,
                       SSL** ssl /* output */)
{
  int ret = 0;
  SSL* s;
  int connect_status;

  s = SSL_new(ssl_ctx);
  if (s == NULL)
  {
    ret = -EPERM;
  }
  else
  {
    /* assign the output value */
    *ssl = s;
  }

  if (!ret)
  {
    SSL_set_fd(s, sockfd);
    connect_status = SSL_connect(s);
    if (connect_status != 1)
    {
      printf("Handshake Error %d\n", SSL_get_error(s, connect_status));
      ERR_print_errors_fp(stderr);
      SSL_free(s);
      ret = -ENOTCONN;
    }
    else
      showCerts(*ssl);
  }

  return ret;
}

static int clientVerifyPeer(SSL* ssl /* input */)
{
  X509* cert = NULL;

  cert = SSL_get_peer_certificate(ssl);

  if (cert)
  {
    long verifyresult;

    switch (SSL_get_verify_result(ssl)) {

    case X509_V_OK:
        printf("Certificate Verification Succeeded\n");
        break;

    default:
        printf("Certificate Verification Failed\n");
        X509_free(cert);
        break;
    }
  }
  else
  {
    printf("There is no client certificate\n");
  }

  return 0;
}

static int clientUp(SSL_CTX** ssl_ctx /* output */,
                    int* sockfd       /* output */,
                    SSL** ssl         /* output */,
                    int* upLevel      /* output */)
{
  int ret = 0;

  ret = clientContextUp(ssl_ctx);

  if (!ret) {
    *upLevel = 1;
    ret = clientSocketUp(sockfd);
  }

  if (!ret) {
    *upLevel = 2;
    ret = clientSslUp(*ssl_ctx, *sockfd, ssl);
  }

  if (!ret) {
    *upLevel = 3;
    ret = clientVerifyPeer(*ssl);
  }

  if (!ret) {
    *upLevel = 4;
  }

  return ret;
}

static int clientDown(SSL_CTX* ssl_ctx /* input */,
                      int sockfd       /* input */,
                      SSL* ssl         /* input */,
                      int upLevel      /* input */)
{
  int ret = 0;

  if (upLevel >= 3)
  {
    (void) SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  if (upLevel >= 2)
    close(sockfd);

  if (upLevel >= 1)
    SSL_CTX_free(ssl_ctx);

  return ret;
}

static void clientTest(SSL* ssl)
{
  char buffer[1024] = "Hello World from Client";
  int bytes_read;

  (void) SSL_write(ssl, buffer, strlen(buffer) + 1);
  bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
  printf("Reply from the server of length %d: %s\n", bytes_read, buffer);
}

int main(void)
{
  int ret = 0;
  SSL_CTX* ssl_ctx;
  int sockfd;
  SSL* ssl;
  int upLevel = 0;

  ret = clientUp(&ssl_ctx, &sockfd, &ssl, &upLevel);

  if (!ret)
    clientTest(ssl);

  if (!ret)
    ret = clientDown(ssl_ctx, sockfd, ssl, upLevel);

  return (ret ? EXIT_FAILURE : EXIT_SUCCESS);
}
