/*! \file main.c
 *  \brief main() function for chirc server
 *
 *  This module provides the main() function for the server,
 *  which parses the command-line arguments to the chirc executable.
 *
 *  Code related to running the server should go in the chirc_run function
 *  (found below the main() function)
 */

#include <asm-generic/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <threads.h>
#include <unistd.h>

#include "chirc.h"
#include "connection.h"
#include "ctx.h"
#include "log.h"

/* Forward declaration of chirc_run */
int chirc_run(chirc_ctx_t *ctx);
int chirc_setup_listening_socket(chirc_ctx_t *ctx,
                                 struct sockaddr_in *server_addr,
                                 socklen_t *addrlen);

/* DO NOT modify the contents of the main() function.
 * Add your code in the chirc_run function found below
 * the main() function. */
int main(int argc, char *argv[]) {
  /* Parse command-line parameters */
  int opt;
  sds port = NULL, passwd = NULL, servername = NULL, network_file = NULL;
  int verbosity = 0;

  while ((opt = getopt(argc, argv, "p:o:s:n:vqh")) != -1)
    switch (opt) {
    case 'p':
      port = sdsnew(optarg);
      break;
    case 'o':
      passwd = sdsnew(optarg);
      break;
    case 's':
      servername = sdsnew(optarg);
      break;
    case 'n':
      if (access(optarg, R_OK) == -1) {
        printf("ERROR: No such file: %s\n", optarg);
        exit(-1);
      }
      network_file = sdsnew(optarg);
      break;
    case 'v':
      verbosity++;
      break;
    case 'q':
      verbosity = -1;
      break;
    case 'h':
      printf("Usage: chirc -o OPER_PASSWD [-p PORT] [-s SERVERNAME] [-n "
             "NETWORK_FILE] [(-q|-v|-vv)]\n");
      exit(0);
      break;
    default:
      fprintf(stderr, "ERROR: Unknown option -%c\n", opt);
      exit(-1);
    }

  if (!passwd) {
    fprintf(stderr, "ERROR: You must specify an operator password\n");
    exit(-1);
  }

  if (network_file && !servername) {
    fprintf(stderr, "ERROR: If specifying a network file, you must also "
                    "specify a server name.\n");
    exit(-1);
  }

  /* Set logging level based on verbosity */
  switch (verbosity) {
  case -1:
    chirc_setloglevel(QUIET);
    break;
  case 0:
    chirc_setloglevel(INFO);
    break;
  case 1:
    chirc_setloglevel(DEBUG);
    break;
  case 2:
    chirc_setloglevel(TRACE);
    break;
  default:
    chirc_setloglevel(TRACE);
    break;
  }

  /* Create server context */
  chirc_ctx_t ctx;
  chirc_ctx_init(&ctx);
  ctx.oper_passwd = passwd;

  if (!network_file) {
    /* If running in standalone mode, we have an IRC Network with
     * just one server. We only initialize ctx.network.this_server */
    char hbuf[NI_MAXHOST];
    gethostname(hbuf, sizeof(hbuf));

    ctx.network.this_server = calloc(1, sizeof(chirc_server_t));

    ctx.network.this_server->servername = sdsnew(hbuf);
    ctx.network.this_server->hostname = sdsnew(hbuf);
    ctx.network.this_server->passwd = NULL;
    ctx.network.this_server->conn = NULL;

    if (port) {
      ctx.network.this_server->port = port;
    } else {
      ctx.network.this_server->port = sdsnew("6667");
    }

    serverlog(INFO, NULL, "%s: standalone mode (port %s)", ctx.version,
              ctx.network.this_server->port);
  } else {
    /* If running in network mode, we load the network specification from the
     * network file specified with the -n parameter */
    if (chirc_ctx_load_network(&ctx, network_file, servername) == CHIRC_FAIL) {
      serverlog(CRITICAL, NULL, "Could not load network file.");
      exit(-1);
    }

    serverlog(INFO, NULL, "%s: IRC network mode", ctx.version);

    for (chirc_server_t *s = ctx.network.servers; s != NULL; s = s->hh.next) {
      bool cur_server =
          (strcmp(s->servername, ctx.network.this_server->servername) == 0);
      serverlog(INFO, NULL, "  %s (%s:%s) %s", s->servername, s->hostname,
                s->port, cur_server ? " <--" : "");
    }
  }

  /* Run the server */
  return chirc_run(&ctx);
}

/*!
 * \brief Runs the chirc server
 *
 * This function starts the chirc server and listens for new
 * connections. Each time a new connection is established,
 * a new thread is created to handle that connection
 * (by calling create_connection_thread)
 *
 * In this function, you can assume the ctx parameter is a fully
 * initialized chirc_ctx_t struct. Most notably, ctx->network.this_server->port
 * will contain the port the server must listen on.
 *
 * \param ctx Server context
 * \return 0 on success, non-zero on failure.
 */
int chirc_run(chirc_ctx_t *ctx) {
  /* Your code goes here */
  int active_socket;
  int passive_socket;
  struct sockaddr_in server_addr;
  socklen_t addrlen;

  passive_socket = chirc_setup_listening_socket(ctx, &server_addr, &addrlen);

  if (passive_socket < 0) {
    serverlog(CRITICAL, NULL, "Could not set up a listening socket");
    return CHIRC_FAIL;
  }

  serverlog(INFO, NULL, "Waiting for a connection... ");
  if ((active_socket = accept(passive_socket, (struct sockaddr *)&server_addr,
                              &addrlen)) == -1) {
    serverlog(CRITICAL, NULL, "Socket accept() failed: %s\n");
    close(passive_socket);
    return CHIRC_FAIL;
  }

  /* Create a new connection */
  chirc_connection_t *conn = chirc_new_connection_from_fd(active_socket);
  if (conn == NULL) {
    serverlog(CRITICAL, NULL, "Could not open a connection: %s\n");
    close(active_socket);
    close(passive_socket);
    return CHIRC_FAIL;
  }
  serverlog(INFO, conn, "Accepting new connection\n");

  char *msg = "fuck u";
  if (send(conn->socket, msg, strlen(msg), 0) <= 0) {
    serverlog(CRITICAL, NULL, "Socket send() failed");
    close(active_socket);
    close(passive_socket);
    return CHIRC_FAIL;
  }

  serverlog(INFO, conn, "Message sent: %s\n", msg);

  close(passive_socket);
  close(active_socket);

  return CHIRC_OK;
}

/* Set up the listening socket */
int chirc_setup_listening_socket(chirc_ctx_t *ctx,
                                 struct sockaddr_in *server_addr,
                                 socklen_t *addrlen) {
  int passive_socket;
  struct addrinfo hints, *res;
  int yes = 1;
  int status;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET; // accept both ipv4 and ipv6
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(ctx->network.this_server->hostname,
                            ctx->network.this_server->port, &hints, &res)) !=
      0) {
    serverlog(CRITICAL, NULL, "getaddrinfo failed: %s\n", gai_strerror(status));
    return CHIRC_FAIL;
  }

  /* copy the server address to prevent dangling addrinfo ptr after free */
  memcpy(server_addr, res->ai_addr, sizeof(struct sockaddr));
  *addrlen = res->ai_addrlen;

  passive_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  freeaddrinfo(res);

  if (passive_socket == -1) {
    serverlog(CRITICAL, NULL, "Could not open socket");
    return CHIRC_FAIL;
  }

  /* Set the port of the socket to be reusable */
  if (setsockopt(passive_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) ==
      -1) {
    serverlog(CRITICAL, NULL, "Socket setsockop() failed");
    close(passive_socket);
    return CHIRC_FAIL;
  }

  if ((bind(passive_socket, (struct sockaddr *)server_addr, *addrlen)) == -1) {
    serverlog(CRITICAL, NULL, "Socket bind() failed");
    close(passive_socket);
    return CHIRC_FAIL;
  }

  if (listen(passive_socket, 5) == -1) {
    serverlog(CRITICAL, NULL, "Socket listen() failed");
    close(passive_socket);
    return CHIRC_FAIL;
  }

  return passive_socket;
}
