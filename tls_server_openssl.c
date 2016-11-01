#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "client_server.h"

static int serverContextInit(SSL_CTX** ssl_ctx /* output */)
{
  int ret = 0;
  SSL_CTX* ctx;

  /* define TLS method */

  ctx = SSL_CTX_new(TLSv1_server_method());

  /* load certificate */

  if (!ret &&
      SSL_CTX_use_certificate_file(ctx,
                                   TLS_SERVER_CERT,
                                   SSL_FILETYPE_PEM) <= 0)
  {
    ret = -EPERM;
  }

  if (!ret &&
      SSL_CTX_use_PrivateKey_file(ctx,
                                  TLS_SERVER_KEY,
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
      !SSL_CTX_load_verify_locations(ctx, TLS_CA_CERT, NULL))
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

static int serverContextUp(SSL_CTX** ssl_ctx /* output */)
{
  int ret = 0;

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ret = serverContextInit(ssl_ctx);

  return ret;
}

static int serverSocketUp(int* sockfd /* output */)
{
  int ret = 0;
  int fd;
  struct sockaddr_in addr;
  int sockopt = 1;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    perror("socket\n");
    ret = -EPERM;
  }

  if (!ret)
  {
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TLS_SERVER_LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*) &sockopt,
               sizeof(int));

    /*
    strncpy(&(addr.sun_path[1]),
            TLS_SERVER_ADDR,
            strlen(TLS_SERVER_ADDR) + 1);
    */

    ret = bind(fd, (struct sockaddr*) &addr, sizeof(addr));

    if (ret)
    {
      perror("bind");
      ret = -errno;
    }
  }

  if (!ret)
  {
    ret = listen(fd, 1024);
    if (ret)
    {
      printf("Error on listen\n");
      ret = -errno;
    }
    else
    {
      printf("Server is listening on port %d\n", TLS_SERVER_LISTEN_PORT);
    }
  }

  if (!ret)
    /* assign the output value */
    *sockfd = fd;
  else if (fd >= 0)
    close(fd);

  return ret;
}

static int serverSslUp(SSL_CTX* ssl_ctx /* input */,
                       int sockfd       /* input */,
                       SSL** ssl        /* output */)
{
  int ret = 0;
  SSL* s;
  int accept_status;

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
    accept_status = SSL_accept(s);
    if (accept_status != 1)
    {
      printf("Handshake Error %d\n", SSL_get_error(s, ret));
      SSL_free(s);
      ret = -ENOTCONN;
    }
  }

  return ret;
}

static int serverVerifyPeer(SSL* ssl /* input */)
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
        sk_X509_free(cert);
        break;
    }
  }
  else
  {
    printf("There is no client certificate\n");
  }

  return 0;
}

static int serverUp(SSL_CTX** ssl_ctx /* output */,
                    int* sockfd       /* output */,
                    int* upLevel      /* output */)
{
  int ret = 0;

  ret = serverContextUp(ssl_ctx);

  if (!ret) {
    *upLevel = 1;
    ret = serverSocketUp(sockfd);
  }

  if (!ret) {
    *upLevel = 2;
  }

  return ret;
}

static int serverDown(SSL_CTX* ssl_ctx /* input */,
                      int sockfd       /* input */,
                      int upLevel      /* input */)
{
  int ret = 0;

  if (upLevel >= 2)
    close(sockfd);

  if (upLevel >= 1)
    SSL_CTX_free(ssl_ctx);

  return ret;
}

static void serverTest(SSL* ssl)
{
  char buffer[1024];
  int bytes_read = 0;
  int len;

  bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
  if (bytes_read > 0)
  {
    len = strlen(" and Server");
    strncpy(&buffer[bytes_read], " and Server", len);
    buffer[bytes_read + len] = '\0';
    SSL_write(ssl, buffer, bytes_read + len + 1);
  }
  else
  {
    printf("Read Error %d\n", SSL_get_error(ssl, bytes_read));
  }
}

static int serverWork(SSL_CTX* ssl_ctx /* input */,
                      int sockfd       /* input */,
                      int upLevel      /* input */)
{
  int ret = 0;
  SSL* ssl;
  int client_sockfd;
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  int workUpLevel = upLevel;

  client_sockfd = accept(sockfd, (struct sockaddr*) &addr, &addrlen);
  printf("Connection %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

  ret = serverSslUp(ssl_ctx, client_sockfd, &ssl);

  if (!ret)
  {
    workUpLevel = 3;
    ret = serverVerifyPeer(ssl);
  }

  if (!ret)
  {
    workUpLevel = 4;
    serverTest(ssl);
  }

  if (!ret && workUpLevel >= 3)
  {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    workUpLevel = upLevel;
  }

  ssl = NULL;

  close(client_sockfd);
  client_sockfd = -1;

  return ret;
}

int main(void)
{
  int ret = 0;
  SSL_CTX* ssl_ctx;
  int sockfd;
  int upLevel = 0;

  ret = serverUp(&ssl_ctx, &sockfd, &upLevel);

  if (!ret)
    /* diverge */
    while (1)
      serverWork(ssl_ctx, sockfd, upLevel);

  /* close the connection in case of error */
  serverDown(ssl_ctx, sockfd, upLevel);

  return (ret ? EXIT_FAILURE : EXIT_SUCCESS);
}
