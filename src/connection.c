/* See connection.h for details about the functions in this module */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "chirc.h"
#include "connection.h"
#include "ctx.h"
#include "handlers.h"
#include "log.h"
#include "message.h"
#include "utils.h"

/* See connection.h */
void chirc_connection_init(chirc_connection_t *conn) {
  conn->type = CONN_TYPE_UNKNOWN;

  conn->hostname = NULL;
  conn->port = 0;
}

chirc_connection_t *chirc_new_connection_from_fd(int sockfd) {
  struct sockaddr_in peer_addr;
  socklen_t addrlen;
  chirc_connection_t *conn =
      (chirc_connection_t *)calloc(1, sizeof(chirc_connection_t));
  if (conn == NULL) {
    serverlog(CRITICAL, NULL, "Connection: calloc failed()\n");
    return NULL;
  }
  chirc_connection_init(conn);
  conn->socket = sockfd;

  if (getpeername(sockfd, (struct sockaddr *)&peer_addr, &addrlen) < 0) {
    serverlog(CRITICAL, NULL, "Connection: getpeername() failed\n");
    return NULL;
  }
  char ipstr[INET_ADDRSTRLEN];
  if (inet_ntop(peer_addr.sin_family, &peer_addr, ipstr, sizeof(ipstr)) < 0) {
    serverlog(CRITICAL, NULL, "Connection: inet_ntop failed() \n");
    return NULL;
  }
  conn->hostname = sdsnew(ipstr);
  char port[6];
  int len = sprintf(port, "%d", peer_addr.sin_port);
  port[len] = 0;
  conn->port = sdsnew(port);

  return conn;
}

/* See connection.h */
void chirc_connection_free(chirc_connection_t *conn) {
  sdsfree(conn->hostname);
}

/* See connection.h */
int chirc_connection_send_message(chirc_ctx_t *ctx, chirc_connection_t *conn,
                                  chirc_message_t *msg) {
  /* Your code here */
  return CHIRC_OK;
}

/* See connection.h */
int chirc_connection_create_thread(chirc_ctx_t *ctx,
                                   chirc_connection_t *connection) {
  /* Your code here */

  return CHIRC_OK;
}
