/* EzWebSocket
 *
 * Copyright © 2017 Clemens Kresser
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "config.h"

#include "socket_client.h"
#include "utils/ref_count.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ezwebsocket_log.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif /* HAVE_OPENSSL */

//! the minimum buffer allocation size
#define MIN_ALLOC_SIZE 2048

//! States of the socket client
enum socket_client_state {
  //! disconnected state
  SOCKET_CLIENT_STATE_DISCONNECTED,
  //! disconnect request state
  SOCKET_CLIENT_STATE_DISCONNECT_REQUEST,
  //! connected state
  SOCKET_CLIENT_STATE_CONNECTED,
};

//! structure that contains information about a socket client
struct socket_client_desc {
  //! callback function that gets called when data is received
  size_t (*socket_onMessage)(void *socketUserData, void *socketDesc, void *sessionData, void *msg,
                             size_t len);
  //! callback function that gets called when the socket is opened
  void *(*socket_onOpen)(void *socketUserData, void *socketDesc);
  //! callback function that gets called when the socket is closed
  void (*socket_onClose)(void *socketUserData, void *socketDesc, void *sessionData);
  //! Pointer to the socket user data
  void *socketUserData;
  //! the thread ID of the socket client thread
  pthread_t tid;
  //! indicates that the tid is valid
  bool tidValid;
  //! dynamic buffer for storing the received data
  struct dyn_buffer buffer;
  //! pointer to the session data
  void *sessionData;
  //! the socket descriptor
  int socketFd;
  //! the state of the socket
  volatile enum socket_client_state state;
  //! indicates if the task is still running
  volatile bool taskRunning;
  //! init done signal
  pthread_mutex_t initDoneSignal;
#ifdef HAVE_OPENSSL
  SSL_CTX *ssl_ctx;
  SSL *ssl;
#endif
};

/**
 * \brief The socket client thread
 *
 * \param *socketDescriptor Pointer to the socket descriptor
 *
 * \return NULL
 */
static void *
socketClientThread(void *socketDescriptor)
{
  struct socket_client_desc *socketDesc = socketDescriptor;
  fd_set readfds;
  int n;
  size_t count;
  int increase;
  size_t bytesFree;
  bool first;
  struct timeval tv;

  // wait for start signal
  pthread_mutex_lock(&socketDesc->initDoneSignal);

  if (socketDesc->socket_onOpen != NULL)
    socketDesc->sessionData = socketDesc->socket_onOpen(socketDesc->socketUserData, socketDesc);

  while (socketDesc->state == SOCKET_CLIENT_STATE_CONNECTED) {
    tv.tv_sec = 0;
    tv.tv_usec = 300000;
    FD_ZERO(&readfds);
    FD_SET(socketDesc->socketFd, &readfds);
    if (select(socketDesc->socketFd + 1, &readfds, NULL, NULL, &tv) > 0) {
      if (FD_ISSET(socketDesc->socketFd, &readfds)) {
        first = true;
        increase = 1;
        do {
          bytesFree = DYNBUFFER_BYTES_FREE(&socketDesc->buffer);
          if (DYNBUFFER_BYTES_FREE(&socketDesc->buffer) < MIN_ALLOC_SIZE) {
            dynBuffer_increase_to(&(socketDesc->buffer), MIN_ALLOC_SIZE * increase);
            bytesFree = DYNBUFFER_BYTES_FREE(&socketDesc->buffer);
            increase++;
          }
#ifdef HAVE_OPENSSL
          if (socketDesc->ssl)
            n = SSL_read(socketDesc->ssl, DYNBUFFER_WRITE_POS(&(socketDesc->buffer)), bytesFree);
          else
#endif /* HAVE_OPENSSL */
            n = recv(socketDesc->socketFd, DYNBUFFER_WRITE_POS(&(socketDesc->buffer)), bytesFree,
                     MSG_DONTWAIT);
          if (first && (n == 0)) {
            socketDesc->state = SOCKET_CLIENT_STATE_DISCONNECTED;
            break;
          }
          first = false;

          if (n >= 0)
            DYNBUFFER_INCREASE_WRITE_POS((&(socketDesc->buffer)), n);
          else
            break;
        } while (((size_t) n == bytesFree) && (socketDesc->state == SOCKET_CLIENT_STATE_CONNECTED));

        if (socketDesc->state == SOCKET_CLIENT_STATE_CONNECTED) {
          do {
            count = socketDesc->socket_onMessage(socketDesc->socketUserData, socketDesc,
                                                 socketDesc->sessionData,
                                                 DYNBUFFER_BUFFER(&(socketDesc->buffer)),
                                                 DYNBUFFER_SIZE(&(socketDesc->buffer)));
            dynBuffer_removeLeadingBytes(&(socketDesc->buffer), count);
          } while (count && DYNBUFFER_SIZE(&(socketDesc->buffer)) &&
                   (socketDesc->state == SOCKET_CLIENT_STATE_CONNECTED));
        }
      }
    }
  }

  dynBuffer_delete(&(socketDesc->buffer));

  if (socketDesc->socket_onClose != NULL)
    socketDesc->socket_onClose(socketDesc->socketUserData, socketDesc, socketDesc->sessionData);

  socketDesc->state = SOCKET_CLIENT_STATE_DISCONNECTED;
  socketDesc->taskRunning = false;

  return NULL;
}

/**
 * \brief Sends the given data over the given socket
 *
 * \param *socketDescriptor Pointer to the socket descriptor
 * \param *msg Pointer to the data
 * \param len The length of the data
 *
 * \return 0 if successful else -1
 */
int
socketClient_send(void *socketDescriptor, void *msg, size_t len)
{
  struct socket_client_desc *socketDesc = socketDescriptor;
  int rc;
  if (socketDesc == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "error socket descriptor is NULL\n");
    return -1;
  }

  if (socketDesc->state != SOCKET_CLIENT_STATE_CONNECTED)
    return -1;

#ifdef HAVE_OPENSSL
  if (socketDesc->ssl)
    rc = SSL_write(socketDesc->ssl, msg, len);
  else
#endif /* HAVE_OPENSSL */
    rc = send(socketDesc->socketFd, msg, len, MSG_NOSIGNAL);
  if (rc == -1) {
    ezwebsocket_log(EZLOG_ERROR, "send failed: %s\n", strerror(errno));
  }
  return ((size_t) rc == len ? 0 : -1);
}

/**
 * \brief Starts the socket client
 *        must be called after socketClient_open
 *
 * \param *socketDescriptor Pointer to the socket descriptor
 */
void
socketClient_start(void *socketDescriptor)
{
  struct socket_client_desc *socketDesc = socketDescriptor;

  pthread_mutex_unlock(&socketDesc->initDoneSignal);
}

/**
 * \brief Opens a socket client
 *
 * \param *socketInit Pointer to the socket_init struct
 * \param *socketUserData Pointer to the the userdata
 *
 * \return Pointer to the socket descriptor
 */
void *
socketClient_open(struct socket_client_init *socketInit, void *socketUserData)
{
  struct socket_client_desc *socketDesc = malloc(sizeof(struct socket_client_desc));
  if (socketDesc == NULL) {
    return NULL;
  }

  memset(socketDesc, 0, sizeof(struct socket_client_desc));

  socketDesc->socketUserData = socketUserData;
  socketDesc->socket_onOpen = socketInit->socket_onOpen;
  socketDesc->socket_onClose = socketInit->socket_onClose;
  socketDesc->socket_onMessage = socketInit->socket_onMessage;
  socketDesc->state = SOCKET_CLIENT_STATE_DISCONNECTED;

  pthread_mutex_init(&socketDesc->initDoneSignal, NULL);
  pthread_mutex_lock(&socketDesc->initDoneSignal);

  dynBuffer_init(&socketDesc->buffer);

  socketDesc->socketFd = socket(AF_INET, SOCK_STREAM, 0);
  if (socketDesc->socketFd < 0) {
    ezwebsocket_log(EZLOG_ERROR, "failed to create socket\n");
    goto ERROR;
  }

  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  if (setsockopt(socketDesc->socketFd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout,
                 sizeof(timeout)) < 0)
    ezwebsocket_log(EZLOG_ERROR, "setsockopt failed\n");

  if (setsockopt(socketDesc->socketFd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout,
                 sizeof(timeout)) < 0)
    ezwebsocket_log(EZLOG_ERROR, "setsockopt failed\n");

  struct sockaddr_in server;

  server.sin_addr.s_addr = inet_addr(socketInit->address);
  server.sin_family = AF_INET;
  server.sin_port = htons(socketInit->port);

  // Connect to remote server
  if (connect(socketDesc->socketFd, (struct sockaddr *) &server, sizeof(server)) < 0) {
    ezwebsocket_log(EZLOG_WARNING, "connection failed\n");
    goto ERROR;
  }

  int optval = socketInit->keepalive == true;

  if (setsockopt(socketDesc->socketFd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
    ezwebsocket_log(EZLOG_ERROR, "setsockopt SO_KEEPALIVE failed\n");
  }

  optval = socketInit->keep_idle_sec;
  if (setsockopt(socketDesc->socketFd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) < 0) {
    ezwebsocket_log(EZLOG_ERROR, "setsockopt TCP_KEEPIDLE failed\n");
  }

  optval = socketInit->keep_cnt;
  if (setsockopt(socketDesc->socketFd, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) < 0) {
    ezwebsocket_log(EZLOG_ERROR, "setsockopt TCP_KEEPCNT failed\n");
  }

  optval = socketInit->keep_intvl;
  if (setsockopt(socketDesc->socketFd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) < 0) {
    ezwebsocket_log(EZLOG_ERROR, "setsockopt TCP_KEEPINTVL failed\n");
  }

#ifdef HAVE_OPENSSL
  if (socketInit->secure) {
    ezwebsocket_log(EZLOG_DEBUG, "use secure websocket\n");
    socketDesc->ssl_ctx = SSL_CTX_new(SSLv23_method());
    socketDesc->ssl = SSL_new(socketDesc->ssl_ctx);
    SSL_set_fd(socketDesc->ssl, socketDesc->socketFd);
    if (SSL_connect(socketDesc->ssl) != 1) {
      ezwebsocket_log(EZLOG_ERROR, "TLS/SSL handshake failed\n");
      goto ERROR;
    }
  }
#else
  if (socketInit->secure) {
    ezwebsocket_log(EZLOG_ERROR, "openssl not compiled in - cannot use secure websocket");
    abort();
  }
#endif /* HAVE_OPENSSL */

  socketDesc->state = SOCKET_CLIENT_STATE_CONNECTED;
  socketDesc->taskRunning = true;

  if (pthread_create(&socketDesc->tid, NULL, socketClientThread, socketDesc) != 0) {
    socketDesc->state = SOCKET_CLIENT_STATE_DISCONNECTED;
    socketDesc->taskRunning = false;
    ezwebsocket_log(EZLOG_ERROR, "failed to create socket client thread\n");
    goto ERROR;
  } else {
    socketDesc->tidValid = true;
  }

  return socketDesc;

ERROR:
  socketClient_close(socketDesc);
  return NULL;
}

/**
 * \brief Closes the socket client
 *
 * \param *socketDescriptor Pointer to the socket descriptor
 */
void
socketClient_close(void *socketDescriptor)
{
  struct socket_client_desc *socketDesc = socketDescriptor;

  if (socketDesc == NULL)
    return;

  socketDesc->state = SOCKET_CLIENT_STATE_DISCONNECT_REQUEST;
  while (socketDesc->taskRunning)
    usleep(30000);

  pthread_mutex_unlock(&socketDesc->initDoneSignal);
  pthread_mutex_destroy(&socketDesc->initDoneSignal);

  if (socketDesc->tidValid) {
    socketDesc->state = SOCKET_CLIENT_STATE_DISCONNECTED;
    pthread_join(socketDesc->tid, NULL);
    socketDesc->tidValid = false;
    dynBuffer_delete(&socketDesc->buffer);
  }

  if (socketDesc->socketFd != -1) {
    close(socketDesc->socketFd);
    socketDesc->socketFd = -1;
  }

  free(socketDesc);
}

/**
 * \brief Closes the connection, but doesn't free ressources
 *
 * \param *socketDescriptor Pointer to the socket descriptor
 */
void
socketClient_closeConnection(void *socketDescriptor)
{
  struct socket_client_desc *socketDesc = socketDescriptor;
  socketDesc->state = SOCKET_CLIENT_STATE_DISCONNECT_REQUEST;
}
