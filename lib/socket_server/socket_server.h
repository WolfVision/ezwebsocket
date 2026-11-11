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

#ifndef SOCKET_SERVER_H_
#define SOCKET_SERVER_H_

#include <stdbool.h>
#include <stddef.h>

//! prototype for the socket connection descriptor
struct socket_connection_desc;
//! prototype for the socket server descriptor
struct socket_server_desc;

//! structure with data needed to create a socket server
struct socket_server_init {
  //! callback that is called when data is received
  size_t (*socket_onMessage)(void *socketUserData, void *connectionDesc, void *connectionUserData,
                             void *msg, size_t len);
  //! callback that is called when a new connection is established
  void *(*socket_onOpen)(void *socketUserData, struct socket_connection_desc *connectionDesc);
  //! callback that is called when a connection is closed
  void (*socket_onClose)(void *socketUserData, void *connectionDesc, void *connectionUserData);
  //! callback that is called when the connection has no data to process
  bool (*socket_onIdle)(void *socketUserData, void *connectionDesc, void *connectionUserData);
  //! the listening port as string
  const char *port;
  //! the listening address as string
  const char *address;
};

void
socketServer_closeConnection(struct socket_connection_desc *socketConnectionDesc);
int
socketServer_send(struct socket_connection_desc *connectionDesc, void *msg, size_t len);
struct socket_server_desc *
socketServer_open(struct socket_server_init *socketInit, void *socketUserData);
void
socketServer_close(struct socket_server_desc *socketDesc);

const char *
socket_get_server_ip(struct socket_connection_desc *desc);
const char *
socket_get_peer_ip(struct socket_connection_desc *desc);
#endif /* SOCKET_SERVER_H_ */
