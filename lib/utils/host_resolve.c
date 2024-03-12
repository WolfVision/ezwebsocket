/* EzWebSocket
 *
 * Copyright © 2024 Stefan Ursella
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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <ezwebsocket_log.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_resolve.h"

#define MAX_IPS 10

void
host_resolve_free_ips(char **ips)
{
  int idx = 0;

  if (!ips || !ips[0])
    return;

  while (ips[idx]) {
    ezwebsocket_log(EZLOG_WARNING, "free [%d] %s\n", idx, ips[idx]);
    free(ips[idx++]);
  }
}

void
host_uri_free(struct host_resolve_uri *uri)
{
  if (!uri)
    return;

  free(uri->schema);
  free(uri->user);
  free(uri->password);
  free(uri->host);
  free(uri->path);
  free(uri->query);
  free(uri);
}

// [schema://[user[:password]@]]host[:port][/path][?query][#fragment]
struct host_resolve_uri *
host_resolve_get_parse_uri(const char *host)
{
  struct host_resolve_uri *uri = NULL;
  char *p_cpy_host, *cpy_host, *ptr;
  size_t len;

  if (!host || !(len = strlen(host)))
    return NULL;

  uri = calloc(1, sizeof(*uri));

  cpy_host = strdup(host);
  p_cpy_host = cpy_host;

  // schema://
  if ((ptr = strstr(p_cpy_host, "://"))) {
    *ptr = '\0';
    if (!strlen(p_cpy_host)) {
      ezwebsocket_log(EZLOG_ERROR, "unexpected schema\n");
      goto err_out;
    }
    uri->schema = strdup(p_cpy_host);
    p_cpy_host = ptr + 3;
  }

  if (!p_cpy_host)
    goto err_out;

  // host must start with number or letter
  if (!isalnum(p_cpy_host[0])) {
    ezwebsocket_log(EZLOG_ERROR, "unexpected hostname\n");
    goto err_out;
  }
  // user[:password]@
  if ((ptr = strstr(p_cpy_host, "@"))) {
    char *ptr2;
    *ptr++ = '\0';
    // user:password
    if ((ptr2 = strstr(p_cpy_host, ":"))) {
      *ptr2++ = '\0';
      if (!strlen(ptr2)) {
        ezwebsocket_log(EZLOG_ERROR, "password missing\n");
        goto err_out;
      }
      uri->password = strdup(ptr2);
    }
    if (!strlen(p_cpy_host)) {
      ezwebsocket_log(EZLOG_ERROR, "username missing\n");
      goto err_out;
    }
    uri->user = strdup(p_cpy_host);
    p_cpy_host = ptr;
  }

  if (!p_cpy_host)
    goto err_out;
  // host[:port][/path][?query]
  if ((ptr = strstr(p_cpy_host, "?"))) {
    *ptr++ = '\0';
    uri->query = strdup(ptr);
  }

  // host[:port][/path]
  if ((ptr = strstr(p_cpy_host, "/"))) {
    *ptr++ = '\0';
    uri->path = strdup(ptr);
  }

  // host[:port]
  if ((ptr = strstr(p_cpy_host, ":"))) {
    *ptr++ = '\0';
    if (!strlen(ptr)) {
      ezwebsocket_log(EZLOG_ERROR, "unexpected port\n");
      goto err_out;
    }
    uri->port = atoi(ptr);
  }

  // no host --> no valid uri
  if (!p_cpy_host || !strlen(p_cpy_host)) {
    ezwebsocket_log(EZLOG_ERROR, "no hostname found\n");
    goto err_out;
  }
  // host
  uri->host = strdup(p_cpy_host);

  free(cpy_host);
  return uri;
err_out:
  free(cpy_host);
  host_uri_free(uri);
  return NULL;
}

char **
host_resolve_get_ips(const char *host)
{
  char **array;
  struct addrinfo hints = { 0 };
  struct addrinfo *ai, *res = NULL;
  int idx = 0;

  array = calloc(MAX_IPS + 1, sizeof(*array));

  hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo(host, NULL, &hints, &res)) {
    ezwebsocket_log(EZLOG_ERROR, "error %m\n");
    return NULL;
  }

  for (ai = res; ai && idx <= MAX_IPS; ai = ai->ai_next) {
    switch (ai->ai_addr->sa_family) {
    case AF_INET6: {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *) ai->ai_addr;
      char buf[INET6_ADDRSTRLEN];
      const char *ipaddr;

      if (ai->ai_addrlen < sizeof(*addr))
        break;

      if (IN6_IS_ADDR_V4MAPPED(&(addr->sin6_addr))) {
        struct sockaddr_in sin_addr;

        sin_addr.sin_family = AF_INET;
        sin_addr.sin_port = addr->sin6_port;
        memcpy(&(sin_addr.sin_addr.s_addr), addr->sin6_addr.s6_addr + 12, 4);

        ipaddr = inet_ntop(AF_INET, &sin_addr.sin_addr, buf, sizeof(buf));
      } else {

        ipaddr = inet_ntop(AF_INET6, &addr->sin6_addr, buf, sizeof(buf));
      }
      if (!ipaddr)
        break;

      array[idx++] = strdup(ipaddr);
    } break;

    case AF_INET: {
      struct sockaddr_in *addr = (struct sockaddr_in *) ai->ai_addr;
      char buf[INET_ADDRSTRLEN];
      const char *ipaddr;

      if (ai->ai_addrlen < sizeof(*addr))
        break;

      ipaddr = inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));

      if (!ipaddr)
        break;

      array[idx++] = strdup(ipaddr);
    } break;

    default:
      break;
    }
  }

  freeaddrinfo(res);
  return array;
}
