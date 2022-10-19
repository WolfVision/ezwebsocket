/* EzWebSocket
 *
 * Copyright © 2017 Clemens Kresser
 * Copyright © 2021 Stefan Ursella
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

#ifndef SOCKET_CLIENT_SOCKET_CLIENT_H_
#define SOCKET_CLIENT_SOCKET_CLIENT_H_

#include "utils/dyn_buffer.h"
#include <stdbool.h>
#include <stddef.h>

//! structure with data needed to create a socket client
struct socket_client_init {
  //! callback that should be called when a message is received use NULL if not used
  size_t (*socket_onMessage)(void *socketUserData, void *socketDesc, void *sessionData, void *msg,
                             size_t len);
  //! callback that should be called when the socket is connected use NULL if not used
  void *(*socket_onOpen)(void *socketUserData, void *socketDesc);
  //! callback that should be called when the socket is closed use NULL if not used
  void (*socket_onClose)(void *socketUserData, void *socketDesc, void *sessionData);
  //! the remote port we want to connect to
  unsigned short port;
  //! the address we want to connect to
  const char *address;
  //! Enable or disable keepalive
  bool keepalive;
  //! How long to wait before sending out the first probe on an idle connection
  int keep_idle_sec;
  //! The number of unanswered probes required to force closure of the socket
  int keep_cnt;
  //! The frequency of keepalive packets after the first one is sent
  int keep_intvl;
  int secure;
};

int
socketClient_send(void *socketDescriptor, void *msg, size_t len);
void
socketClient_start(void *socketDescriptor);
void *
socketClient_open(struct socket_client_init *socketInit, void *socketUserData);
void
socketClient_close(void *socketDescriptor);
void
socketClient_closeConnection(void *socketDescriptor);

#endif /* SOCKET_CLIENT_SOCKET_CLIENT_H_ */
