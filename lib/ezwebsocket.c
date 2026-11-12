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

#define _GNU_SOURCE
#include "ref_count.h"
#include "socket_client/socket_client.h"
#include "socket_server/socket_server.h"
#include "stringck.h"
#include "utils/base64.h"
#include "utils/utf8.h"
#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <ezwebsocket.h>
#include <ezwebsocket_log.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#else
#include "utils/sha1.h"
#endif
//! timeout for fragmented messages
#define MESSAGE_TIMEOUT_S             30
#define HANDSHAKE_TIMEOUT_S           10

//! if payload length in the websocket header is smaller or equal than this
//! the extended payload is not used
#define MAX_DEFAULT_PAYLOAD_LENGTH    125
//! value of the websocket payload length if the extended 16-bit length is used
#define EXTENDED_16BIT_PAYLOAD_LENGTH 126
//! value of the websocket payload length if the extended 64-bit length is used
#define EXTENDED_64BIT_PAYLOAD_LENGTH 127

static bool
secureRandomBytes(unsigned char *buffer, size_t length)
{
  int random_fd = open("/dev/urandom", O_RDONLY);
  size_t offset = 0;

  if (random_fd < 0)
    return false;

  while (offset < length) {
    ssize_t received = read(random_fd, &buffer[offset], length - offset);
    if (received < 0 && errno == EINTR)
      continue;
    if (received <= 0) {
      close(random_fd);
      return false;
    }
    offset += (size_t) received;
  }

  close(random_fd);
  return true;
}

//! the different websocket states
enum ws_state { WS_STATE_HANDSHAKE, WS_STATE_CONNECTED, WS_STATE_CLOSED };

//! the websocket op-codes
enum ws_opcode {
  WS_OPCODE_CONTINUATION = 0x00,
  WS_OPCODE_TEXT = 0x01,
  WS_OPCODE_BINARY = 0x02,
  WS_OPCODE_DISCONNECT = 0x08,
  WS_OPCODE_PING = 0x09,
  WS_OPCODE_PONG = 0x0A,
};

//! the websocket connection types
enum ws_type { WS_TYPE_CLIENT, WS_TYPE_SERVER };

//! descriptor for the websocket server
struct websocket_server_desc {
  //! callback that is called when a message is received on the websocket
  void (*ws_onMessage)(void *websocketUserData, struct websocket_connection_desc *connectionDesc,
                       void *connectionUserData, enum ws_data_type dataType, void *msg, size_t len);
  //! callback that is called when the websocket is connected (legacy version)
  void *(*ws_onOpenLegacy)(struct websocket_server_desc *wsDesc,
                           struct websocket_connection_desc *connectionDesc);
  //! callback that is called when the websocket is connected
  void *(*ws_onOpen)(void *websocketUserData, struct websocket_server_desc *wsDesc,
                     struct websocket_connection_desc *connectionDesc);
  //! callback that is called when the websocket is closed (legacy version)
  void (*ws_onCloseLegacy)(void *websocketUserData,
                           struct websocket_connection_desc *connectionDesc,
                           void *connectionUserData);
  //! callback that is called when the websocket is closed
  void (*ws_onClose)(struct websocket_server_desc *wsDesc, void *websocketUserData,
                     struct websocket_connection_desc *connectionDesc, void *userData);
  //! pointer to the socket descriptor
  void *socketDesc;
  //! pointer to the user data
  void *wsSocketUserData;
};

//! structure that holds message data
struct last_message {
  //! the type of data (WS_DATA_TYPE_TEXT or WS_DATA_TYPE_BINARY)
  enum ws_data_type dataType;
  //! indicates if the first message was received
  bool firstReceived;
  //! indicates if the message is complete
  bool complete;
  //! handle that is used to store the state if using fragmented strings
  unsigned long utf8Handle;
  //! the length of the message
  size_t len;
  //! pointer to the data
  char *data;
};

//! structure that contains information about the websocket connection
struct websocket_connection_desc {
  //! indicates if it is a websocket client or a websocket server
  enum ws_type wsType;
  //! pointer to the socket client descriptor
  void *socketClientDesc;
  //! the connection state of the websocket (handshake, connected, closed)
  volatile enum ws_state state;
  //! information about the last received message
  struct last_message lastMessage;
  //! pointer to the connection user data
  void *connectionUserData;
  //! stores the time for message timeouts
  struct timespec timeout;
  //! stores when the server-side handshake started
  struct timespec handshakeStartedAt;
  //! union for either client or server descriptor
  union {
    //! pointer to the websocket client descriptor (in case of client mode)
    struct websocket_client_desc *wsClientDesc;
    //! pointer to the websocket server descriptor (in case of server mode)
    struct websocket_server_desc *wsServerDesc;
  } wsDesc;
};

//! structure that contains information about a client connection
struct websocket_client_desc {
  //! callback that is called when a message is received on the websocket
  void (*ws_onMessage)(void *socketUserData, struct websocket_connection_desc *connectionDesc,
                       void *connectionUserData, enum ws_data_type dataType, void *msg, size_t len);
  //! callback that is called when the websocket is connected
  void *(*ws_onOpen)(void *socketUserData, struct websocket_connection_desc *connectionDesc);
  //! callback that is called when the websocket is closed
  void (*ws_onClose)(void *socketUserData, struct websocket_connection_desc *connectionDesc,
                     void *connectionUserData);
  //! pointer to the socket descriptor
  void *socketDesc;
  //! pointer to the user data
  void *wsUserData;
  //! the websocket connection descriptor for the current connection
  struct websocket_connection_desc *connection;
  //! the address of the host
  char *address;
  //! the port of the websocket host
  char *port;
  //! the endpoint where the websocket should connect
  char *endpoint;
  //! pointer to the websocket key that is used to validate it's a websocket connection
  char *wsKey;
};

//! the magic key to calculate the websocket handshake accept key
#define WS_ACCEPT_MAGIC_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/**
 * \brief Calculates the Sec-WebSocket-Accept from the Sec-WebSocket-Key
 *
 * \param *key Pointer to the key that should be used
 *
 * \return The string containing the Sec-WebSocket-Accept (must be freed after use)
 */
static char *
calculateSecWebSocketAccept(const char *key)
{
  char concatString[64];
  unsigned char sha1Hash[21];

  snprintf(concatString, sizeof(concatString), "%s" WS_ACCEPT_MAGIC_KEY, key);

#ifdef HAVE_OPENSSL
  SHA1((const unsigned char *) concatString, strlen(concatString), sha1Hash);
#else
  SHA1((char *) sha1Hash, concatString, strlen(concatString));
#endif /* HAVE_OPENSSL */
  return base64_encode(sha1Hash, 20);
}

// GET /chat HTTP/1.1
// Host: example.com:8000
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
// Sec-WebSocket-Version: 13

//! websocket handshake key identifier
#define WS_HS_KEY_ID          "Sec-WebSocket-Key:"
//! websocket handshake key identifier length
#define WS_HS_KEY_LEN         25
#define WS_HANDSHAKE_MAX_SIZE 8192

static bool
ascii_equal(const char *value, size_t value_len, const char *expected)
{
  size_t i;

  if (value_len != strlen(expected))
    return false;

  for (i = 0; i < value_len; i++) {
    if (tolower((unsigned char) value[i]) != tolower((unsigned char) expected[i]))
      return false;
  }

  return true;
}

static size_t
find_crlf(const char *data, size_t start, size_t end)
{
  size_t i;

  for (i = start; i + 1 < end; i++) {
    if (data[i] == '\r' && data[i + 1] == '\n')
      return i;
  }

  return SIZE_MAX;
}

static bool
header_value_has_token(const char *value, size_t value_len, const char *token)
{
  size_t start = 0;
  size_t end;

  while (start < value_len) {
    while (start < value_len &&
           (value[start] == ' ' || value[start] == '\t' || value[start] == ','))
      start++;
    end = start;
    while (end < value_len && value[end] != ',')
      end++;
    while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t'))
      end--;
    if (ascii_equal(&value[start], end - start, token))
      return true;
    start = end;
    while (start < value_len && value[start] != ',')
      start++;
  }

  return false;
}

static int
base64_value(unsigned char value)
{
  if (value >= 'A' && value <= 'Z')
    return value - 'A';
  if (value >= 'a' && value <= 'z')
    return value - 'a' + 26;
  if (value >= '0' && value <= '9')
    return value - '0' + 52;
  if (value == '+')
    return 62;
  if (value == '/')
    return 63;
  return -1;
}

static bool
valid_websocket_key(const char *value, size_t value_len)
{
  size_t i;

  if (value_len != WS_HS_KEY_LEN - 1 || value[22] != '=' || value[23] != '=')
    return false;

  for (i = 0; i < 22; i++) {
    if (base64_value((unsigned char) value[i]) < 0)
      return false;
  }

  return (base64_value((unsigned char) value[21]) & 0x0f) == 0;
}

/**
 * \brief Parses the http header and extracts the Sec-WebSocket-Key
 *
 * \param *wsHeader Pointer to the string with the header
 * \param len Length of the header
 * \param[out] *key Pointer to where the key should be stored (should be at least WS_HS_KEY_LEN big)
 *
 * \return 1 if complete and valid, 0 if incomplete, -1 if invalid
 *
 */
static int
parseHttpHeader(const char *wsHeader, size_t len, char *key, size_t *headerLen)
{
  size_t header_end = SIZE_MAX;
  size_t request_line_end;
  size_t first_space = SIZE_MAX;
  size_t second_space = SIZE_MAX;
  size_t position;
  size_t line_end;
  size_t i;
  bool host_seen = false;
  bool upgrade_seen = false;
  bool connection_seen = false;
  bool version_seen = false;
  bool key_seen = false;

  for (i = 0; i + 3 < len; i++) {
    if (memcmp(&wsHeader[i], "\r\n\r\n", 4) == 0) {
      header_end = i + 4;
      break;
    }
  }
  if (header_end == SIZE_MAX)
    return len >= WS_HANDSHAKE_MAX_SIZE ? -1 : 0;
  if (header_end > WS_HANDSHAKE_MAX_SIZE)
    return -1;

  request_line_end = find_crlf(wsHeader, 0, header_end - 2);
  if (request_line_end == SIZE_MAX)
    return -1;
  for (i = 0; i < request_line_end; i++) {
    if (wsHeader[i] == ' ') {
      if (first_space == SIZE_MAX)
        first_space = i;
      else {
        second_space = i;
        break;
      }
    }
  }
  if (first_space != 3 || second_space == SIZE_MAX || !ascii_equal(wsHeader, first_space, "GET") ||
      second_space == first_space + 1 ||
      !ascii_equal(&wsHeader[second_space + 1], request_line_end - second_space - 1, "HTTP/1.1"))
    return -1;
  for (i = first_space + 1; i < second_space; i++) {
    if ((unsigned char) wsHeader[i] <= 0x20 || (unsigned char) wsHeader[i] == 0x7f)
      return -1;
  }

  position = request_line_end + 2;
  while (position < header_end - 2) {
    size_t colon = SIZE_MAX;
    size_t value_start;
    size_t value_end;

    line_end = find_crlf(wsHeader, position, header_end);
    if (line_end == SIZE_MAX)
      return -1;
    if (line_end == position)
      break;
    if (wsHeader[position] == ' ' || wsHeader[position] == '\t')
      return -1;
    for (i = position; i < line_end; i++) {
      if (wsHeader[i] == ':') {
        colon = i;
        break;
      }
      if (!isalnum((unsigned char) wsHeader[i]) && !strchr("!#$%&'*+-.^_`|~", wsHeader[i]))
        return -1;
    }
    if (colon == SIZE_MAX || colon == position)
      return -1;

    value_start = colon + 1;
    value_end = line_end;
    while (value_start < value_end &&
           (wsHeader[value_start] == ' ' || wsHeader[value_start] == '\t'))
      value_start++;
    while (value_end > value_start &&
           (wsHeader[value_end - 1] == ' ' || wsHeader[value_end - 1] == '\t'))
      value_end--;
    for (i = value_start; i < value_end; i++) {
      unsigned char character = (unsigned char) wsHeader[i];
      if ((character < 0x20 && character != '\t') || character == 0x7f)
        return -1;
    }

    if (ascii_equal(&wsHeader[position], colon - position, "Host")) {
      if (host_seen || value_start == value_end)
        return -1;
      host_seen = true;
    } else if (ascii_equal(&wsHeader[position], colon - position, "Upgrade")) {
      if (value_start == value_end)
        return -1;
      upgrade_seen = upgrade_seen || header_value_has_token(&wsHeader[value_start],
                                                            value_end - value_start, "websocket");
    } else if (ascii_equal(&wsHeader[position], colon - position, "Connection")) {
      if (value_start == value_end)
        return -1;
      connection_seen = connection_seen ||
                        header_value_has_token(&wsHeader[value_start], value_end - value_start,
                                               "upgrade");
    } else if (ascii_equal(&wsHeader[position], colon - position, "Sec-WebSocket-Version")) {
      if (version_seen || !ascii_equal(&wsHeader[value_start], value_end - value_start, "13"))
        return -1;
      version_seen = true;
    } else if (ascii_equal(&wsHeader[position], colon - position, "Sec-WebSocket-Key")) {
      if (key_seen || !valid_websocket_key(&wsHeader[value_start], value_end - value_start))
        return -1;
      memcpy(key, &wsHeader[value_start], WS_HS_KEY_LEN - 1);
      key[WS_HS_KEY_LEN - 1] = '\0';
      key_seen = true;
    }

    position = line_end + 2;
  }

  if (!host_seen || !upgrade_seen || !connection_seen || !version_seen || !key_seen)
    return -1;

  *headerLen = header_end;
  return 1;
}

//! blueprint for the websocket handshake reply
#define WS_HANDSHAKE_REPLY_BLUEPRINT                                                               \
  "HTTP/1.1 101 Switching Protocols\r\n"                                                           \
  "Upgrade: websocket\r\n"                                                                         \
  "Connection: Upgrade\r\n"                                                                        \
  "Sec-WebSocket-Accept: %s\r\n"                                                                   \
  "\r\n"

/**
 * \brief Sends the websocket handshake reply
 *
 * \param *socketConnectionDesc The connection descriptor of the socket
 * \param *replyKey The calculated Sec-WebSocket-Accept key
 *
 * \return -1 on error 0 if successful
 *
 */
static int
sendWsHandshakeReply(struct socket_connection_desc *socketConnectionDesc, const char *replyKey)
{
  char replyHeader[strlen(WS_HANDSHAKE_REPLY_BLUEPRINT) + 28];

  if (snprintf(replyHeader, sizeof(replyHeader), WS_HANDSHAKE_REPLY_BLUEPRINT, replyKey) >=
      (int) sizeof(replyHeader)) {
    ezwebsocket_log(EZLOG_ERROR, "problem with the handshake reply key (buffer to small)\n");
    return -1;
  }

  return socketServer_send(socketConnectionDesc, replyHeader, strlen(replyHeader));
}

//! websocket handshake reply identifier
#define WS_HS_REPLY_ID "Sec-WebSocket-Accept:"

/**
 * \brief checks if we've received the correct handshake reply
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param *header Pointer to the header
 * \param[in,out] len Input the length of the message output the length of the header
 *
 * \return 1 if valid, 0 if incomplete, -1 if invalid
 */
static int
checkWsHandshakeReply(struct websocket_connection_desc *wsConnectionDesc, const char *header,
                      size_t len, size_t *headerLen)
{
  if (wsConnectionDesc->wsType == WS_TYPE_SERVER)
    return -1;

  struct websocket_client_desc *wsDesc = wsConnectionDesc->wsDesc.wsClientDesc;
  size_t end = SIZE_MAX;
  size_t request_line_end;
  size_t position;
  size_t line_end;
  size_t accepted_start = 0;
  size_t accepted_len = 0;
  size_t i;
  bool upgrade_seen = false;
  bool connection_seen = false;
  bool accept_seen = false;
  char *accept_string;

  for (i = 0; i + 3 < len; i++) {
    if (memcmp(&header[i], "\r\n\r\n", 4) == 0) {
      end = i + 4;
      break;
    }
  }
  if (end == SIZE_MAX)
    return len >= WS_HANDSHAKE_MAX_SIZE ? -1 : 0;
  if (end > WS_HANDSHAKE_MAX_SIZE)
    return -1;

  request_line_end = find_crlf(header, 0, end - 2);
  if (request_line_end == SIZE_MAX || request_line_end < 12 ||
      memcmp(header, "HTTP/1.1 101", 12) != 0 || (request_line_end > 12 && header[12] != ' '))
    return -1;

  position = request_line_end + 2;
  while (position < end - 2) {
    size_t colon = SIZE_MAX;
    size_t value_start;
    size_t value_end;

    line_end = find_crlf(header, position, end);
    if (line_end == SIZE_MAX)
      return -1;
    if (line_end == position)
      break;
    if (header[position] == ' ' || header[position] == '\t')
      return -1;
    for (i = position; i < line_end; i++) {
      if (header[i] == ':') {
        colon = i;
        break;
      }
      if (!isalnum((unsigned char) header[i]) &&
          !strchr("!#$%&'*+-.^_`|~", (unsigned char) header[i]))
        return -1;
    }
    if (colon == SIZE_MAX || colon == position)
      return -1;

    value_start = colon + 1;
    value_end = line_end;
    while (value_start < value_end && (header[value_start] == ' ' || header[value_start] == '\t'))
      value_start++;
    while (value_end > value_start &&
           (header[value_end - 1] == ' ' || header[value_end - 1] == '\t'))
      value_end--;
    for (i = value_start; i < value_end; i++) {
      unsigned char character = (unsigned char) header[i];
      if ((character < 0x20 && character != '\t') || character == 0x7f)
        return -1;
    }

    if (ascii_equal(&header[position], colon - position, "Upgrade")) {
      if (value_start == value_end)
        return -1;
      upgrade_seen = upgrade_seen || header_value_has_token(&header[value_start],
                                                            value_end - value_start, "websocket");
    } else if (ascii_equal(&header[position], colon - position, "Connection")) {
      if (value_start == value_end)
        return -1;
      connection_seen = connection_seen ||
                        header_value_has_token(&header[value_start], value_end - value_start,
                                               "upgrade");
    } else if (ascii_equal(&header[position], colon - position, "Sec-WebSocket-Accept")) {
      if (accept_seen || value_start == value_end)
        return -1;
      accepted_start = value_start;
      accepted_len = value_end - value_start;
      accept_seen = true;
    }

    position = line_end + 2;
  }

  if (!upgrade_seen || !connection_seen || !accept_seen)
    return -1;

  accept_string = calculateSecWebSocketAccept(wsDesc->wsKey);
  if (accept_string == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "calculateSecWebSocketAccept failed\n");
    return -1;
  }

  i = accepted_len == strlen(accept_string) &&
      memcmp(&header[accepted_start], accept_string, accepted_len) == 0;
  free(accept_string);
  if (!i)
    return -1;

  *headerLen = end;
  return 1;
}

/**
 * \brief Sends the websocket handshake request
 *
 * \param *wsConnectionDesc Pointer to the websocket client descriptor
 *
 * \return True if successful else false
 */
static bool
sendWsHandshakeRequest(struct websocket_connection_desc *wsConnectionDesc)
{
  unsigned char wsKeyBytes[16];
  char *requestHeader = NULL;
  bool success = false;
  struct websocket_client_desc *wsDesc = wsConnectionDesc->wsDesc.wsClientDesc;

  if (!secureRandomBytes(wsKeyBytes, sizeof(wsKeyBytes))) {
    ezwebsocket_log(EZLOG_ERROR, "failed to get a secure handshake key\n");
    goto EXIT;
  }

  wsDesc->wsKey = base64_encode(wsKeyBytes, sizeof(wsKeyBytes));
  if (asprintf(&requestHeader,
               "GET %s HTTP/1.1\r\n"
               "Host: %s:%s\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n",
               wsDesc->endpoint, wsDesc->address, wsDesc->port, wsDesc->wsKey) < 0) {
    ezwebsocket_log(EZLOG_ERROR, "asprintf failed\n");
    goto EXIT;
  }

  if (socketClient_send(wsConnectionDesc->socketClientDesc, requestHeader, strlen(requestHeader)) ==
      -1) {
    ezwebsocket_log(EZLOG_ERROR, "socketClient_send failed\n");
    goto EXIT;
  }

  success = true;

EXIT:
  if (!success) {
    free(wsDesc->wsKey);
    wsDesc->wsKey = NULL;
  }
  free(requestHeader);
  return success;
}

static bool
validClientRequestPart(const char *value)
{
  const unsigned char *character = (const unsigned char *) value;

  if (!character || !*character)
    return false;

  while (*character) {
    if (*character <= 0x20 || *character == 0x7f)
      return false;
    character++;
  }

  return true;
}

// Frame format of a websocket:
// ​​
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-------+-+-------------+-------------------------------+
//     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//     | |1|2|3|       |K|             |                               |
//     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//     |     Extended payload length continued, if payload len == 127  |
//     + - - - - - - - - - - - - - - - +-------------------------------+
//     |                               |Masking-key, if MASK set to 1  |
//     +-------------------------------+-------------------------------+
//     | Masking-key (continued)       |          Payload Data         |
//     +-------------------------------- - - - - - - - - - - - - - - - +
//     :                     Payload Data continued ...                :
//     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//     |                     Payload Data continued ...                |
//     +---------------------------------------------------------------+
//
// copied form
// https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
// licensed under CC-BY-SA 2.5.

//! structure that holds all data from the websocket header
struct ws_header {
  //! fin flag received
  bool fin;
  //! the websocket opcode
  enum ws_opcode opcode;
  //! the length of the payload
  size_t payloadLength;
  //! indicates if the message is masked
  bool masked;
  //! the mask (undefined if not masked)
  unsigned char mask[4];
  //! the offset of the payload
  unsigned char payloadStartOffset;
};

/**
 * \brief Prints the websocket header (for debugging purpose only)
 *
 * \param *header Pointer to the header
 *
 */
static void __attribute__((unused))
printWsHeader(const struct ws_header *header)
{
  ezwebsocket_log(EZLOG_DEBUG, "----ws header----\n");
  ezwebsocket_log_continue(EZLOG_DEBUG, "opcode:%d\n", header->opcode);
  ezwebsocket_log_continue(EZLOG_DEBUG, "fin:%d\n", header->fin);
  ezwebsocket_log_continue(EZLOG_DEBUG, "masked:%d\n", header->masked);
  ezwebsocket_log_continue(EZLOG_DEBUG, "pllength:%zu\n", header->payloadLength);
  ezwebsocket_log_continue(EZLOG_DEBUG, "ploffset:%u\n", header->payloadStartOffset);
  ezwebsocket_log_continue(EZLOG_DEBUG, "-----------------\n");
}

/**
 * \brief Parses the header of a websocket message
 *
 * \param *data Pointer to the message received from the socket
 * \param len The length of the data
 * \param[out] *header Pointer to where the header should be written to
 *
 * \return 1 if successful 0 if msg to short else -1
 */
static int
parseWebsocketHeader(const unsigned char *data, size_t len, struct ws_header *header)
{
  if (len < 2) {
    return 0;
  }

  header->fin = (data[0] & 0x80) ? true : false;
  header->opcode = data[0] & 0x0F;
  if (data[0] & 0x70) // reserved bits must be 0
  {
    ezwebsocket_log(EZLOG_ERROR, "reserved bits must be 0\n");
    return -1;
  }
  switch (header->opcode) {
  case WS_OPCODE_CONTINUATION:
  case WS_OPCODE_TEXT:
  case WS_OPCODE_BINARY:
  case WS_OPCODE_PING:
  case WS_OPCODE_PONG:
  case WS_OPCODE_DISCONNECT:
    break;

  default:
    ezwebsocket_log(EZLOG_ERROR, "opcode unknown (%d)\n", header->opcode);
    return -1;
  }

  header->masked = (data[1] & 0x80) ? true : false;
  size_t i, lengthNumBytes;
  size_t maxPayloadLength = header->opcode >= WS_OPCODE_DISCONNECT ? MAX_DEFAULT_PAYLOAD_LENGTH
                                                                   : MAX_WEBSOCKET_PAYLOAD_LENGTH;

  header->payloadLength = 0;

  // decode payload length
  if ((data[1] & 0x7F) <= MAX_DEFAULT_PAYLOAD_LENGTH) {
    header->payloadLength = data[1] & 0x7F;
    lengthNumBytes = 0; // not really true but needed for further calculations
  } else if ((data[1] & 0x7F) == EXTENDED_16BIT_PAYLOAD_LENGTH) {
    if (len < 4) {
      return 0;
    }
    lengthNumBytes = 2;
  } else // data[1] == EXTENDED_64BIT_PAYLOAD_LENGTH
  {
    if (len < 10) {
      return 0;
    }
    lengthNumBytes = 8;
  }

  for (i = 0; i < lengthNumBytes; i++) {
    size_t byte = data[2 + i];
    if (byte > maxPayloadLength || header->payloadLength > (maxPayloadLength - byte) / 256) {
      return header->opcode >= WS_OPCODE_DISCONNECT ? -1 : -2;
    }
    header->payloadLength = header->payloadLength * 256 + byte;
  }

  if (header->payloadLength > maxPayloadLength)
    return header->opcode >= WS_OPCODE_DISCONNECT ? -1 : -2;

  ezwebsocket_log(EZLOG_DEBUG, "payloadlength:%zu\n", header->payloadLength);

  if (header->masked) {
    if (len < 2 + lengthNumBytes + 4) {
      return 0;
    }
    for (i = 0; i < 4; i++) {
      header->mask[i] = data[2 + lengthNumBytes + i];
    }

    header->payloadStartOffset = 2 + lengthNumBytes + 4;
  } else
    header->payloadStartOffset = 2 + lengthNumBytes;

  return 1;
}

/**
 * \brief creates the websocket header from the given variables
 *
 * \param[out] *buffer Pointer to the buffer where the header should be written to
 *                 should be able to hold at least 10 bytes
 * \param opcode The opcode that should be used for the header
 * \param fin Fin bit (is this the last frame (true) or will more follow (false))
 * \param masked True => add a mask, false => add no mask
 * \param mask The mask that should be used (ignored in case masked is false)
 * \param len The length of the payload
 *
 * \return The length of the header
 */
static int
createWebsocketHeader(unsigned char *buffer, enum ws_opcode opcode, bool fin, bool masked,
                      unsigned long mask, size_t len)
{
  int cnt, i;

  buffer[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0F);

  // masked bit always 0 for server->client replies
  if (len <= MAX_DEFAULT_PAYLOAD_LENGTH) {
    buffer[1] = len;
    cnt = 2;
  } else if (len <= 0xFFFF) {
    buffer[1] = EXTENDED_16BIT_PAYLOAD_LENGTH;
    buffer[2] = len >> 8;
    buffer[3] = len & 0xFF;
    cnt = 4;
  } else {
    buffer[1] = EXTENDED_64BIT_PAYLOAD_LENGTH;
    cnt = 2;

    for (i = 7; i > -1; i--) {
      buffer[cnt] = ((uint64_t) len >> (i * 8)) & 0xFF;
      cnt++;
    }
  }

  if (masked) {
    buffer[1] |= 0x80;
    for (i = 3; i > -1; i--) {
      buffer[cnt] = (mask >> (i * 8)) & 0xFF;
      cnt++;
    }
  }

  return cnt;
}

/**
 * \brief Copies the data in the buffer pointed by from to the buffer pointed by to and mask
 *        them
 *
 * \param *to Pointer to where the data should copied masked
 * \param *from Pointer to the original data
 * \param mask The mask that shoud be used (32-bit)
 * \param len The length of the data that should be copied
 *
 * \note The masking algorithm is big endian XOR
 */
static void
copyMasked(unsigned char *to, const unsigned char *from, unsigned long mask, size_t len)
{
  unsigned char byteMask[4];
  size_t i;
  unsigned char maskIdx = 0;

  // big endian
  byteMask[0] = mask >> 24 & 0xFF;
  byteMask[1] = mask >> 16 & 0xFF;
  byteMask[2] = mask >> 8 & 0xFF;
  byteMask[3] = mask >> 0 & 0xFF;

  for (i = 0; i < len; i++) {
    *to = *from ^ byteMask[maskIdx];
    maskIdx = (maskIdx + 1) % 4;
    to++;
    from++;
  }
}

/**
 * \brief Sends data through websockets with custom opcodes
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param opcode The opcode to use
 * \param fin True if this is the last frame of a sequence else false
 * \param masked True => send masked (client to server) else false (server to client)
 * \param *msg The payload data
 * \param len The payload length
 *
 * \return 0 if successful else -1
 */
static int
sendDataLowLevel(struct websocket_connection_desc *wsConnectionDesc, enum ws_opcode opcode,
                 bool fin, bool masked, const void *msg, size_t len)
{
  unsigned char header[14]; // the maximum size of a websocket header is 14
  unsigned char maskBytes[4];
  int headerLength;
  unsigned char *sendBuffer;
  int rc = -1;
  unsigned long mask = 0;

  if (wsConnectionDesc->state == WS_STATE_CLOSED)
    return -1;

  if (opcode >= WS_OPCODE_DISCONNECT && (!fin || len > MAX_DEFAULT_PAYLOAD_LENGTH)) {
    ezwebsocket_log(EZLOG_ERROR, "invalid outgoing control frame\n");
    return -1;
  }

  if (opcode < WS_OPCODE_DISCONNECT && len > MAX_WEBSOCKET_PAYLOAD_LENGTH) {
    ezwebsocket_log(EZLOG_ERROR, "outgoing message exceeds configured maximum\n");
    return -1;
  }

  if (masked) {
    if (!secureRandomBytes(maskBytes, sizeof(maskBytes))) {
      ezwebsocket_log(EZLOG_ERROR, "failed to get a secure frame mask\n");
      return -1;
    }
    mask = ((unsigned long) maskBytes[0] << 24) | ((unsigned long) maskBytes[1] << 16) |
           ((unsigned long) maskBytes[2] << 8) | (unsigned long) maskBytes[3];
  }

  headerLength = createWebsocketHeader(header, opcode, fin, masked, mask, len);

  if (len > SIZE_MAX - (size_t) headerLength)
    return -1;

  sendBuffer = malloc(headerLength + len);
  if (!sendBuffer)
    return -1;
  memcpy(sendBuffer, header, headerLength);
  if (len) {
    if (masked) {
      copyMasked(&sendBuffer[headerLength], msg, mask, len);
    } else
      memcpy(&sendBuffer[headerLength], msg, len);
  }

  switch (wsConnectionDesc->wsType) {
  case WS_TYPE_SERVER:
    rc = socketServer_send(wsConnectionDesc->socketClientDesc, sendBuffer, len + headerLength);
    break;

  case WS_TYPE_CLIENT:
    rc = socketClient_send(wsConnectionDesc->socketClientDesc, sendBuffer, len + headerLength);
    break;
  }
  free(sendBuffer);

  ezwebsocket_log(EZLOG_DEBUG, "%s retv:%d\n", __func__, rc);

  return rc;
}

/**
 * \brief Checks if the given close code is valid
 *
 * \param code The code that should be checked
 *
 * \return True if code is valid else false
 */
static bool
checkCloseCode(enum ws_close_code code)
{
  if (code < 1000)
    return false;

  if (code > 4999)
    return false;

  if ((code >= 1012) & (code <= 1014))
    return false;

  if ((code >= 1016) && (code < 3000))
    return false;

  switch (code) {
  case WS_CLOSE_CODE_RESERVED_0:
  case WS_CLOSE_CODE_RESERVED_1:
  case WS_CLOSE_CODE_RESERVED_2:
  case WS_CLOSE_CODE_RESERVED_3:
    return false;

  default:
    return true;
  }
}

//! the states of a websocket message
enum ws_msg_state {
  WS_MSG_STATE_ERROR,
  WS_MSG_STATE_INCOMPLETE,
  WS_MSG_STATE_NO_USER_DATA,
  WS_MSG_STATE_USER_DATA,
};

/**
 * \brief Handles the first message (which is sometimes followed by a cont message)
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param *data Pointer to the payload data
 * \param *header Pointer to the parsed websocket header structure
 *
 * \return The message state
 */
static enum ws_msg_state
handleFirstMessage(struct websocket_connection_desc *wsConnectionDesc, const unsigned char *data,
                   struct ws_header *header)
{
  size_t i;

  if (!header->masked && (wsConnectionDesc->wsType == WS_TYPE_SERVER)) {
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }

  if (wsConnectionDesc->lastMessage.data != NULL) {
    ezwebsocket_log(EZLOG_ERROR, "last message not finished\n");
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }

  if (header->payloadLength) // it's allowed to send frames with payload length = 0
  {
    if (header->payloadLength > MAX_WEBSOCKET_PAYLOAD_LENGTH) {
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_MSG_TO_BIG);
      return WS_MSG_STATE_ERROR;
    }

    if (header->fin)
      wsConnectionDesc->lastMessage.data = refcnt_allocate(header->payloadLength, NULL);
    else
      wsConnectionDesc->lastMessage.data = malloc(header->payloadLength);
    if (!wsConnectionDesc->lastMessage.data) {
      ezwebsocket_log(EZLOG_ERROR, "refcnt_allocate failed dropping message\n");
      return WS_MSG_STATE_ERROR;
    }

    if (header->masked) {
      for (i = 0; i < header->payloadLength; i++) {
        wsConnectionDesc->lastMessage.data[i] = data[header->payloadStartOffset + i] ^
                                                header->mask[i % 4];
      }
    } else {
      memcpy(wsConnectionDesc->lastMessage.data, &data[header->payloadStartOffset],
             header->payloadLength);
    }
  }

  wsConnectionDesc->lastMessage.firstReceived = true;
  wsConnectionDesc->lastMessage.complete = header->fin;
  wsConnectionDesc->lastMessage.dataType = header->opcode == WS_OPCODE_TEXT ? WS_DATA_TYPE_TEXT
                                                                            : WS_DATA_TYPE_BINARY;

  wsConnectionDesc->lastMessage.len = header->payloadLength;
  if (wsConnectionDesc->lastMessage.dataType == WS_DATA_TYPE_TEXT) {
    enum utf8_state state;

    wsConnectionDesc->lastMessage.utf8Handle = 0;
    state = utf8_validate(wsConnectionDesc->lastMessage.data, wsConnectionDesc->lastMessage.len,
                          &wsConnectionDesc->lastMessage.utf8Handle);
    if ((header->fin && (state != UTF8_STATE_OK)) || (!header->fin && (state == UTF8_STATE_FAIL))) {
      ezwebsocket_log(EZLOG_ERROR, "no valid utf8 string closing connection\n");
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_INVALID_DATA);
      return WS_MSG_STATE_ERROR;
    }
  }
  if (header->fin)
    return WS_MSG_STATE_USER_DATA;
  else
    return WS_MSG_STATE_NO_USER_DATA;
}

/**
 * \brief Handles a cont message
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param *data Pointer to the payload data
 * \param *header Pointer to the parsed websocket header structure
 *
 * \return The message state
 */
static enum ws_msg_state
handleContMessage(struct websocket_connection_desc *wsConnectionDesc, const unsigned char *data,
                  struct ws_header *header)
{
  size_t i;
  char *temp;

  if (!wsConnectionDesc->lastMessage.firstReceived) {
    ezwebsocket_log(EZLOG_ERROR, "missing last message closing connection\n");
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }

  if (wsConnectionDesc->lastMessage.len > MAX_WEBSOCKET_PAYLOAD_LENGTH ||
      header->payloadLength > MAX_WEBSOCKET_PAYLOAD_LENGTH - wsConnectionDesc->lastMessage.len) {
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_MSG_TO_BIG);
    return WS_MSG_STATE_ERROR;
  }

  if ((wsConnectionDesc->wsType != WS_TYPE_SERVER) == header->masked) {
    ezwebsocket_log(EZLOG_ERROR, "mask bit wrong\n");
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }

  if (wsConnectionDesc->lastMessage.len +
      header->payloadLength) // it's allowed to send frames with payload length = 0
  {
    if (header->fin) {
      temp = refcnt_allocate(wsConnectionDesc->lastMessage.len + header->payloadLength, NULL);
      if (!temp) {
        ezwebsocket_log(EZLOG_ERROR, "refcnt_allocate failed dropping message\n");
        free(wsConnectionDesc->lastMessage.data);
        wsConnectionDesc->lastMessage.data = NULL;
        return WS_MSG_STATE_ERROR;
      }
      memcpy(temp, wsConnectionDesc->lastMessage.data, wsConnectionDesc->lastMessage.len);
      free(wsConnectionDesc->lastMessage.data);
      wsConnectionDesc->lastMessage.data = temp;
    } else {
      temp = realloc(wsConnectionDesc->lastMessage.data,
                     wsConnectionDesc->lastMessage.len + header->payloadLength);
      if (!temp) {
        ezwebsocket_log(EZLOG_ERROR, "realloc failed dropping message\n");
        free(wsConnectionDesc->lastMessage.data);
        wsConnectionDesc->lastMessage.data = NULL;
        return WS_MSG_STATE_ERROR;
      }
      wsConnectionDesc->lastMessage.data = temp;
    }

    if (header->masked) {
      for (i = 0; i < header->payloadLength; i++) {
        wsConnectionDesc->lastMessage
          .data[wsConnectionDesc->lastMessage.len + i] = data[header->payloadStartOffset + i] ^
                                                         header->mask[i % 4];
      }
    } else {
      memcpy(&wsConnectionDesc->lastMessage.data[wsConnectionDesc->lastMessage.len],
             &data[header->payloadStartOffset], header->payloadLength);
    }
  }
  wsConnectionDesc->lastMessage.complete = header->fin;

  if (wsConnectionDesc->lastMessage.dataType == WS_DATA_TYPE_TEXT) {
    enum utf8_state state;
    state = utf8_validate(&wsConnectionDesc->lastMessage.data[wsConnectionDesc->lastMessage.len],
                          header->payloadLength, &wsConnectionDesc->lastMessage.utf8Handle);
    if ((header->fin && state != UTF8_STATE_OK) || (!header->fin && state == UTF8_STATE_FAIL)) {
      ezwebsocket_log(EZLOG_ERROR, "no valid utf8 string closing connection\n");
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_INVALID_DATA);
      return WS_MSG_STATE_ERROR;
    }
  }
  wsConnectionDesc->lastMessage.len += header->payloadLength;

  if (header->fin)
    return WS_MSG_STATE_USER_DATA;
  else
    return WS_MSG_STATE_NO_USER_DATA;
}

/**
 * \brief Handles a ping message and replies with a pong message
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param *data Pointer to the payload data
 * \param *header Pointer to the parsed websocket header structure
 *
 * \return The message state
 */
static enum ws_msg_state
handlePingMessage(struct websocket_connection_desc *wsConnectionDesc, const unsigned char *data,
                  struct ws_header *header)
{
  int rc;
  char *temp;
  size_t i;
  bool masked = (wsConnectionDesc->wsType == WS_TYPE_CLIENT);

  if (header->fin) {
    if (header->payloadLength > MAX_DEFAULT_PAYLOAD_LENGTH) {
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
      return WS_MSG_STATE_NO_USER_DATA;
    } else if (header->masked) {
      if (header->payloadLength) {
        temp = malloc(header->payloadLength);
        if (!temp) {
          ezwebsocket_log(EZLOG_ERROR, "malloc failed dropping message\n");
          return WS_MSG_STATE_ERROR;
        }

        for (i = 0; i < header->payloadLength; i++) {
          temp[i] = data[header->payloadStartOffset + i] ^ header->mask[i % 4];
        }
      } else
        temp = NULL;

      if (sendDataLowLevel(wsConnectionDesc, WS_OPCODE_PONG, true, masked, temp,
                           header->payloadLength) == 0)
        rc = WS_MSG_STATE_NO_USER_DATA;
      else
        rc = WS_MSG_STATE_ERROR;
      free(temp);
      return rc;
    } else {
      ezwebsocket_log(EZLOG_INFO, "SEND PONG MSG\n");
      if (sendDataLowLevel(wsConnectionDesc, WS_OPCODE_PONG, true, masked,
                           &data[header->payloadStartOffset], header->payloadLength) == 0)
        return WS_MSG_STATE_NO_USER_DATA;
      else
        return WS_MSG_STATE_ERROR;
    }
  } else {
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }
}

/**
 * \brief Handles a pong message
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param *data Pointer to the payload data
 * \param *header Pointer to the parsed websocket header structure
 *
 * \return the message state
 */
static enum ws_msg_state
handlePongMessage(struct websocket_connection_desc *wsConnectionDesc, const unsigned char *data,
                  struct ws_header *header)
{
  (void) data;

  if (header->fin && (header->payloadLength <= MAX_DEFAULT_PAYLOAD_LENGTH)) {
    ezwebsocket_log(EZLOG_WARNING, "PONG msg is not handled\n");
    // Pongs are ignored now because actually we also don't send pings
    return WS_MSG_STATE_NO_USER_DATA;
  } else {
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }
}

/**
 * \brief handles a disconnect message and replies with a disconnect message
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param *data Pointer to the payload data
 * \param *header Pointer to the parsed websocket header structure
 *
 * \return the message state
 */
static enum ws_msg_state
handleDisconnectMessage(struct websocket_connection_desc *wsConnectionDesc,
                        const unsigned char *data, struct ws_header *header)
{
  size_t i;
  unsigned long utf8Handle = 0;

  if ((header->fin) && (header->payloadLength != 1) &&
      (header->payloadLength <= MAX_DEFAULT_PAYLOAD_LENGTH)) {
    enum ws_close_code code;

    if (!header->payloadLength) {
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_NORMAL);
      return WS_MSG_STATE_NO_USER_DATA;
    } else if (header->masked == (wsConnectionDesc->wsType == WS_TYPE_SERVER)) {
      char tempBuffer[MAX_DEFAULT_PAYLOAD_LENGTH];

      if (header->masked) {
        for (i = 0; i < header->payloadLength; i++) {
          tempBuffer[i] = data[header->payloadStartOffset + i] ^ header->mask[i % 4];
        }
      } else {
        memcpy(tempBuffer, &data[header->payloadStartOffset], header->payloadLength);
      }

      code = (((unsigned char) tempBuffer[0]) << 8) | ((unsigned char) tempBuffer[1]);
      if (checkCloseCode(code) == false) {
        websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
        return WS_MSG_STATE_ERROR;
      } else if ((header->payloadLength == 2) ||
                 (UTF8_STATE_OK ==
                  utf8_validate(&tempBuffer[2], header->payloadLength - 2, &utf8Handle))) {
        websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_NORMAL);
        return WS_MSG_STATE_NO_USER_DATA;
      } else {
        websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_INVALID_DATA);
        return WS_MSG_STATE_ERROR;
      }
    } else {
      ezwebsocket_log(EZLOG_ERROR, "close frame mask bit wrong\n");
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
      return WS_MSG_STATE_ERROR;
    }
  } else {
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }
}

const char *
opcode2str(int op_code)
{
  switch (op_code) {
  case WS_OPCODE_TEXT:
    return "WS_OPCODE_TEXT";
    break;
  case WS_OPCODE_BINARY:
    return "WS_OPCODE_BINARY";
    break;
  case WS_OPCODE_CONTINUATION:
    return "WS_OPCODE_CONTINUATION";
    break;
  case WS_OPCODE_PING:
    return "WS_OPCODE_PING";
    break;
  case WS_OPCODE_PONG:
    return "WS_OPCODE_PONG";
    break;
  case WS_OPCODE_DISCONNECT:
    return "WS_OPCODE_DISCONNECT";
    break;
  }
  return "unknown op code";
}

/**
 * \brief parses a message and stores it to the client descriptor
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param *data Pointer to the received data
 * \param len The length of the data
 * \param header The parsed header struct (as parsed by parseWebsocketHeader)
 *
 * \return One of WS_MSG_STATE_x
 */
static enum ws_msg_state
parseMessage(struct websocket_connection_desc *wsConnectionDesc, const unsigned char *data,
             size_t len, struct ws_header *header)
{
  enum ws_msg_state rc;

  ezwebsocket_log(EZLOG_DEBUG, "->len:%zu opcode: %d == %s\n", len, header->opcode,
                  opcode2str(header->opcode));

  if (header->payloadStartOffset > len || header->payloadLength > len - header->payloadStartOffset)
    return WS_MSG_STATE_INCOMPLETE;

  switch (header->opcode) {
  case WS_OPCODE_TEXT:
  case WS_OPCODE_BINARY:
    return handleFirstMessage(wsConnectionDesc, data, header);

  case WS_OPCODE_CONTINUATION:
    return handleContMessage(wsConnectionDesc, data, header);

  case WS_OPCODE_PING:
    return handlePingMessage(wsConnectionDesc, data, header);

  case WS_OPCODE_PONG:
    return handlePongMessage(wsConnectionDesc, data, header);

  case WS_OPCODE_DISCONNECT:
    return handleDisconnectMessage(wsConnectionDesc, data, header);

  default:
    ezwebsocket_log(EZLOG_ERROR, "unknown opcode (%d)\n", header->opcode);
    rc = WS_MSG_STATE_ERROR;
    break;
  }

  return rc;
}

const char *
websocketServer_getPeerIp(struct websocket_connection_desc *wsConnectionDesc)
{
  if (wsConnectionDesc->wsType == WS_TYPE_SERVER)
    return socket_get_peer_ip(wsConnectionDesc->socketClientDesc);
  else
    return NULL;
}

const char *
websocketServer_getServerIp(struct websocket_connection_desc *wsConnectionDesc)
{
  if (wsConnectionDesc->wsType == WS_TYPE_SERVER)
    return socket_get_server_ip(wsConnectionDesc->socketClientDesc);
  else
    return NULL;
}

/**
 * \brief Function that gets called when a connection to a client is established
 *         allocates and initialises the wsClientDesc
 *
 * \param *socketUserData: In this case this is the websocket descriptor
 * \param *socketConnectionDesc The connection descriptor from the socket server
 *
 * \return Pointer to the websocket connection descriptor
 */
static void *
websocketServer_onOpen(void *socketUserData, struct socket_connection_desc *socketConnectionDesc)
{
  struct websocket_server_desc *wsDesc = socketUserData;
  struct websocket_connection_desc *wsConnectionDesc;

  if (wsDesc == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "%s(): wsDesc must not be NULL!\n", __func__);
    return NULL;
  }

  if (socketConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "%s(): socketClientDesc must not be NULL!\n", __func__);
    return NULL;
  }

  wsConnectionDesc = refcnt_allocate(sizeof(struct websocket_connection_desc), NULL);
  if (!wsConnectionDesc) {
    ezwebsocket_log(EZLOG_ERROR, "refcnt_allocate failed\n");
    socketServer_closeConnection(socketConnectionDesc);
    return NULL;
  }

  refcnt_ref(socketConnectionDesc);
  memset(wsConnectionDesc, 0, sizeof(struct websocket_connection_desc));
  wsConnectionDesc->wsType = WS_TYPE_SERVER;
  wsConnectionDesc->socketClientDesc = socketConnectionDesc;
  wsConnectionDesc->state = WS_STATE_HANDSHAKE;
  clock_gettime(CLOCK_MONOTONIC, &wsConnectionDesc->handshakeStartedAt);
  wsConnectionDesc->timeout.tv_nsec = 0;
  wsConnectionDesc->timeout.tv_sec = 0;
  wsConnectionDesc->lastMessage.firstReceived = false;
  wsConnectionDesc->lastMessage.data = NULL;
  wsConnectionDesc->lastMessage.len = 0;
  wsConnectionDesc->lastMessage.complete = false;
  wsConnectionDesc->wsDesc.wsServerDesc = wsDesc;

  return wsConnectionDesc;
}

static bool
websocket_onIdle(void *socketUserData, void *socketConnectionDesc, void *connectionUserData)
{
  struct websocket_connection_desc *wsConnectionDesc = connectionUserData;
  struct timespec now;

  (void) socketUserData;
  (void) socketConnectionDesc;

  if (!wsConnectionDesc)
    return true;

  clock_gettime(CLOCK_MONOTONIC, &now);
  if (wsConnectionDesc->state == WS_STATE_HANDSHAKE && wsConnectionDesc->wsType == WS_TYPE_SERVER) {
    if (now.tv_sec - wsConnectionDesc->handshakeStartedAt.tv_sec >= HANDSHAKE_TIMEOUT_S) {
      socketServer_closeConnection(wsConnectionDesc->socketClientDesc);
      return true;
    }
    return false;
  }

  if (wsConnectionDesc->timeout.tv_sec || wsConnectionDesc->timeout.tv_nsec) {
    time_t elapsed = now.tv_sec - wsConnectionDesc->timeout.tv_sec;
    if (elapsed > MESSAGE_TIMEOUT_S ||
        (elapsed == MESSAGE_TIMEOUT_S && now.tv_nsec >= wsConnectionDesc->timeout.tv_nsec)) {
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_POLICY_VIOLATION);
      return true;
    }
  }

  return false;
}

/**
 * \brief Function that get's called when a websocket client connection is
 *        established
 *
 * \param *socketUserData In this case this is the websocket descriptor
 * \param *socketDesc The socket descriptor of the socket client
 *
 * \return Pointer to the websocket connection descriptor
 */
static void *
websocketClient_onOpen(void *socketUserData, void *socketDesc)
{
  struct websocket_connection_desc *wsConnectionDesc = socketUserData;
  struct websocket_client_desc *wsDesc = wsConnectionDesc->wsDesc.wsClientDesc;
  (void) socketDesc;

  if (sendWsHandshakeRequest(wsConnectionDesc)) {
    return wsDesc->connection;
  } else {
    wsConnectionDesc->state = WS_STATE_CLOSED;
    return NULL;
  }
}

/**
 * \brief gets called when the websocket is closed
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 */
static void
callOnClose(struct websocket_connection_desc *wsConnectionDesc)
{
  switch (wsConnectionDesc->wsType) {
  case WS_TYPE_SERVER:
    if (wsConnectionDesc->wsDesc.wsServerDesc->ws_onClose != NULL) {
      wsConnectionDesc->wsDesc.wsServerDesc
        ->ws_onClose(wsConnectionDesc->wsDesc.wsServerDesc,
                     wsConnectionDesc->wsDesc.wsServerDesc->wsSocketUserData, wsConnectionDesc,
                     wsConnectionDesc->connectionUserData);
    } else if (wsConnectionDesc->wsDesc.wsServerDesc->ws_onCloseLegacy != NULL) {
      wsConnectionDesc->wsDesc.wsServerDesc
        ->ws_onCloseLegacy(wsConnectionDesc->wsDesc.wsServerDesc->wsSocketUserData,
                           wsConnectionDesc, wsConnectionDesc->connectionUserData);
    }
    break;

  case WS_TYPE_CLIENT:
    if (wsConnectionDesc->wsDesc.wsClientDesc->ws_onClose != NULL)
      wsConnectionDesc->wsDesc.wsClientDesc
        ->ws_onClose(wsConnectionDesc->wsDesc.wsClientDesc->wsUserData, wsConnectionDesc,
                     wsConnectionDesc->connectionUserData);
    break;
  }
}

/**
 * \brief function that gets called when a connection to a client is closed
 *         frees the websocket client descriptor
 *
 * \param *socketUserData The websocket descriptor
 * \param *socketConnectionDesc The connection descriptor from the socket server/client
 * \param *wsConnectionDescriptor The websocket connection descriptor
 *
 */
static void
websocket_onClose(void *socketUserData, void *socketConnectionDesc, void *wsConnectionDescriptor)
{
  (void) socketUserData;
  struct websocket_connection_desc *wsConnectionDesc = wsConnectionDescriptor;
  enum ws_type wsType;
  (void) socketConnectionDesc;

  if (wsConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "%s(): wsConnectionDesc must not be NULL!\n", __func__);
    return;
  }

  wsType = wsConnectionDesc->wsType;

  if (wsConnectionDesc->lastMessage.data && wsConnectionDesc->lastMessage.complete)
    refcnt_unref(wsConnectionDesc->lastMessage.data);
  else
    free(wsConnectionDesc->lastMessage.data);
  wsConnectionDesc->lastMessage.data = NULL;

  if (wsConnectionDesc->state == WS_STATE_CONNECTED) {
    wsConnectionDesc->state = WS_STATE_CLOSED;
    callOnClose(wsConnectionDesc);
  } else {
    wsConnectionDesc->state = WS_STATE_CLOSED;
  }

  if (wsType == WS_TYPE_SERVER) // in client mode the connection descriptor is not allocated
  {
    if (wsConnectionDesc->socketClientDesc)
      refcnt_unref(wsConnectionDesc->socketClientDesc);
    wsConnectionDesc->socketClientDesc = NULL;
    refcnt_unref(wsConnectionDesc);
  } else {
    refcnt_unref(wsConnectionDesc);
  }
}

/**
 * \brief Gets called when a message was received on the websocket
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 */
static void
callOnMessage(struct websocket_connection_desc *wsConnectionDesc)
{
  switch (wsConnectionDesc->wsType) {
  case WS_TYPE_SERVER: {
    if (wsConnectionDesc->wsDesc.wsServerDesc->ws_onMessage) {
      wsConnectionDesc->wsDesc.wsServerDesc
        ->ws_onMessage(wsConnectionDesc->wsDesc.wsServerDesc->wsSocketUserData, wsConnectionDesc,
                       wsConnectionDesc->connectionUserData, wsConnectionDesc->lastMessage.dataType,
                       wsConnectionDesc->lastMessage.data, wsConnectionDesc->lastMessage.len);
    }
  } break;

  case WS_TYPE_CLIENT: {
    if (wsConnectionDesc->wsDesc.wsClientDesc->ws_onMessage) {
      wsConnectionDesc->wsDesc.wsClientDesc
        ->ws_onMessage(wsConnectionDesc->wsDesc.wsClientDesc->wsUserData, wsConnectionDesc,
                       wsConnectionDesc->connectionUserData, wsConnectionDesc->lastMessage.dataType,
                       wsConnectionDesc->lastMessage.data, wsConnectionDesc->lastMessage.len);
    }
  } break;
  }
}

/**
 * \brief Function that gets called when a message arrives at the socket server
 *
 * \param *socketUserData In this case this is the websocket descriptor
 * \param *socketConnectionDesc The descriptor of the underlying socket
 * \param *connectionDescriptor The websocket connection descriptor
 * \param *msg Pointer to the buffer containing the data
 * \param len The length of msg
 *
 * \return the amount of bytes read
 *
 */
static size_t
websocket_onMessage(void *socketUserData, void *socketConnectionDesc, void *connectionDescriptor,
                    void *msg, size_t len)
{
  struct websocket_connection_desc *wsConnectionDesc = connectionDescriptor;
  struct ws_header wsHeader = { 0 };
  struct timespec now;
  size_t handshakeHeaderLen;
  int handshakeResult;

  char key[WS_HS_KEY_LEN];
  char *replyKey;

  if (wsConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "%s(): wsConnectionDesc must not be NULL!\n", __func__);
    return 0;
  }

  if (socketConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "%s(): socketConnectionDesc must not be NULL!\n", __func__);
    return 0;
  }

  if (websocket_onIdle(socketUserData, socketConnectionDesc, wsConnectionDesc))
    return len;

  switch (wsConnectionDesc->state) {
  case WS_STATE_HANDSHAKE:
    switch (wsConnectionDesc->wsType) {
    case WS_TYPE_SERVER:
      handshakeResult = parseHttpHeader(msg, len, key, &handshakeHeaderLen);
      if (handshakeResult == 0)
        return 0;
      if (handshakeResult < 0) {
        static const char badRequest
          [] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        socketServer_send(socketConnectionDesc, (void *) badRequest, sizeof(badRequest) - 1);
        socketServer_closeConnection(socketConnectionDesc);
        return len;
      }

      {
        struct websocket_server_desc *wsDesc = socketUserData;

        replyKey = calculateSecWebSocketAccept(key);
        if (replyKey == NULL) {
          ezwebsocket_log(EZLOG_ERROR, "%s(): calculateSecWebSocketAccept failed!\n", __func__);
          return 0;
        }

        ezwebsocket_log(EZLOG_DEBUG, "%s() replyKey:%s\n", __func__, replyKey);

        if (sendWsHandshakeReply(socketConnectionDesc, replyKey) != 0) {
          free(replyKey);
          socketServer_closeConnection(socketConnectionDesc);
          return len;
        }

        free(replyKey);
        wsConnectionDesc->state = WS_STATE_CONNECTED;
        if (wsDesc->ws_onOpen != NULL)
          wsConnectionDesc->connectionUserData = wsDesc->ws_onOpen(wsDesc->wsSocketUserData, wsDesc,
                                                                   wsConnectionDesc);

        if (wsDesc->ws_onOpenLegacy != NULL)
          wsConnectionDesc->connectionUserData = wsDesc->ws_onOpenLegacy(wsDesc, wsConnectionDesc);
        len = handshakeHeaderLen;
      }
      break;

    case WS_TYPE_CLIENT:
      handshakeResult = checkWsHandshakeReply(wsConnectionDesc, msg, len, &handshakeHeaderLen);
      if (handshakeResult == 0)
        return 0;
      if (handshakeResult < 0) {
        ezwebsocket_log(EZLOG_ERROR, "invalid WebSocket handshake response\n");
        wsConnectionDesc->state = WS_STATE_CLOSED;
        socketClient_closeConnection(wsConnectionDesc->socketClientDesc);
        return len;
      }

      {
        struct websocket_client_desc *wsDesc = wsConnectionDesc->wsDesc.wsClientDesc;

        wsConnectionDesc->state = WS_STATE_CONNECTED;

        if (wsDesc->ws_onOpen != NULL)
          wsConnectionDesc->connectionUserData = wsDesc->ws_onOpen(wsDesc->wsUserData,
                                                                   wsConnectionDesc);
        else
          wsConnectionDesc->connectionUserData = NULL;
        len = handshakeHeaderLen;
      }
      break;
    }
    return len;

  case WS_STATE_CONNECTED:
    switch (parseWebsocketHeader(msg, len, &wsHeader)) {
    case -2:
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_MSG_TO_BIG);
      return len;

    case -1:
      ezwebsocket_log(EZLOG_ERROR, "couldn't parse header\n");
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
      return len;

    case 0:
      if (wsConnectionDesc->timeout.tv_sec == 0 && wsConnectionDesc->timeout.tv_nsec == 0)
        clock_gettime(CLOCK_MONOTONIC, &wsConnectionDesc->timeout);
      return 0;
      break;

    case 1:
      break;
    }
    printWsHeader(&wsHeader);

    switch (parseMessage(wsConnectionDesc, msg, len, &wsHeader)) {
    case WS_MSG_STATE_NO_USER_DATA:
      if (wsConnectionDesc->lastMessage.firstReceived && !wsConnectionDesc->lastMessage.complete) {
        if (wsConnectionDesc->timeout.tv_sec == 0 && wsConnectionDesc->timeout.tv_nsec == 0)
          clock_gettime(CLOCK_MONOTONIC, &wsConnectionDesc->timeout);
      } else {
        wsConnectionDesc->timeout.tv_nsec = 0;
        wsConnectionDesc->timeout.tv_sec = 0;
      }
      return wsHeader.payloadLength + wsHeader.payloadStartOffset;

    case WS_MSG_STATE_USER_DATA:
      callOnMessage(wsConnectionDesc);
      if (wsConnectionDesc->lastMessage.data)
        refcnt_unref(wsConnectionDesc->lastMessage.data);
      wsConnectionDesc->lastMessage.data = NULL;
      wsConnectionDesc->lastMessage.complete = false;
      wsConnectionDesc->lastMessage.firstReceived = false;
      wsConnectionDesc->lastMessage.len = 0;
      wsConnectionDesc->timeout.tv_nsec = 0;
      wsConnectionDesc->timeout.tv_sec = 0;
      return wsHeader.payloadLength + wsHeader.payloadStartOffset;

    case WS_MSG_STATE_INCOMPLETE:
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (wsConnectionDesc->timeout.tv_sec == 0 && wsConnectionDesc->timeout.tv_nsec == 0) {
        wsConnectionDesc->timeout = now;
      } else {
        time_t elapsed = now.tv_sec - wsConnectionDesc->timeout.tv_sec;
        if (elapsed > MESSAGE_TIMEOUT_S ||
            (elapsed == MESSAGE_TIMEOUT_S && now.tv_nsec >= wsConnectionDesc->timeout.tv_nsec)) {
          ezwebsocket_log(EZLOG_ERROR, "message timeout\n");
          websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_POLICY_VIOLATION);
          return len;
        }
      }
      return 0;

    case WS_MSG_STATE_ERROR:
      if (wsConnectionDesc->lastMessage.data && wsConnectionDesc->lastMessage.complete)
        refcnt_unref(wsConnectionDesc->lastMessage.data);
      else
        free(wsConnectionDesc->lastMessage.data);
      wsConnectionDesc->lastMessage.data = NULL;
      wsConnectionDesc->lastMessage.len = 0;
      wsConnectionDesc->lastMessage.complete = 0;
      wsConnectionDesc->timeout.tv_sec = 0;
      wsConnectionDesc->timeout.tv_nsec = 0;
      return len;

    default:
      ezwebsocket_log(EZLOG_ERROR, "unexpected return value\n");
      return len;
    }
    break;

  case WS_STATE_CLOSED:
    ezwebsocket_log(EZLOG_ERROR, "websocket closed ignoring message\n");
    return len;

  default:
    break;
  }

  return 0;
}

/**
 * \brief frees the given connection
 *
 * \param *connection pointer to the websocket connection descriptor
 *
 * \note this function is passed to refcnt_allocate to free the connection in
 *       case of websocket client
 */
static void
freeConnection(void *connection)
{
  struct websocket_connection_desc *wsConnectionDesc = connection;

  if (wsConnectionDesc == NULL)
    return;

  if (wsConnectionDesc->wsDesc.wsClientDesc != NULL) {
    if (wsConnectionDesc->socketClientDesc != NULL) {
      socketClient_close(wsConnectionDesc->socketClientDesc);
      wsConnectionDesc->socketClientDesc = NULL;
    }

    free(wsConnectionDesc->wsDesc.wsClientDesc->address);
    wsConnectionDesc->wsDesc.wsClientDesc->address = NULL;
    free(wsConnectionDesc->wsDesc.wsClientDesc->port);
    wsConnectionDesc->wsDesc.wsClientDesc->port = NULL;
    free(wsConnectionDesc->wsDesc.wsClientDesc->endpoint);
    wsConnectionDesc->wsDesc.wsClientDesc->endpoint = NULL;
    free(wsConnectionDesc->wsDesc.wsClientDesc->wsKey);
    wsConnectionDesc->wsDesc.wsClientDesc->wsKey = NULL;
    free(wsConnectionDesc->wsDesc.wsClientDesc);
    wsConnectionDesc->wsDesc.wsClientDesc = NULL;
  }
}

/**
 * \brief Sends binary or text data through websockets
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param dataType The datatype (WS_DATA_TYPE_BINARY or WS_DATA_TYPE_TEXT)
 * \param *msg The payload data
 * \param len The payload length
 *
 * \return 0 if successful else -1
 *
 */
int
websocket_sendData(struct websocket_connection_desc *wsConnectionDesc, enum ws_data_type dataType,
                   const void *msg, size_t len)
{
  unsigned char opcode;
  bool masked = (wsConnectionDesc->wsType == WS_TYPE_CLIENT);

  if (wsConnectionDesc->state != WS_STATE_CONNECTED)
    return -1;

  switch (dataType) {
  case WS_DATA_TYPE_BINARY:
    opcode = WS_OPCODE_BINARY;
    break;

  case WS_DATA_TYPE_TEXT:
    opcode = WS_OPCODE_TEXT;
    break;

  default:
    ezwebsocket_log(EZLOG_ERROR, "unknown data type\n");
    return -1;
  }

  return sendDataLowLevel(wsConnectionDesc, opcode, true, masked, msg, len);
}

/**
 * \brief Sends fragmented binary or text data through websockets
 *         use websocket_sendDataFragmetedCont for further fragments
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param dataType The datatype (WS_DATA_TYPE_BINARY or WS_DATA_TYPE_TEXT)
 * \param *msg The payload data
 * \param len The payload length
 *
 * \return 0 if successful else -1
 *
 */
int
websocket_sendDataFragmentedStart(struct websocket_connection_desc *wsConnectionDesc,
                                  enum ws_data_type dataType, const void *msg, size_t len)
{
  unsigned char opcode;
  bool masked = (wsConnectionDesc->wsType == WS_TYPE_CLIENT);

  if (wsConnectionDesc->state != WS_STATE_CONNECTED)
    return -1;

  switch (dataType) {
  case WS_DATA_TYPE_BINARY:
    opcode = WS_OPCODE_BINARY;
    break;

  case WS_DATA_TYPE_TEXT:
    opcode = WS_OPCODE_TEXT;
    break;

  default:
    ezwebsocket_log(EZLOG_ERROR, "unknown data type\n");
    return -1;
  }

  return sendDataLowLevel(wsConnectionDesc, opcode, false, masked, msg, len);
}

/**
 * \brief Continues a fragmented send
 *         use sendDataFragmentedStop to stop the transmission
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param fin True => this is the last fragment else false
 * \param *msg The payload data
 * \param len The payload length
 *
 * \return 0 if successful else -1
 *
 */
int
websocket_sendDataFragmentedCont(struct websocket_connection_desc *wsConnectionDesc, bool fin,
                                 const void *msg, size_t len)
{
  bool masked = (wsConnectionDesc->wsType == WS_TYPE_CLIENT);

  if (wsConnectionDesc->state != WS_STATE_CONNECTED)
    return -1;

  return sendDataLowLevel(wsConnectionDesc, WS_OPCODE_CONTINUATION, fin, masked, msg, len);
}

/**
 * \brief Closes the given websocket connection
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 * \param code The closing code
 */
void
websocket_closeConnection(struct websocket_connection_desc *wsConnectionDesc,
                          enum ws_close_code code)
{
  unsigned char help[2];
  bool masked = (wsConnectionDesc->wsType == WS_TYPE_CLIENT);

  help[0] = (unsigned long) code >> 8;
  help[1] = (unsigned long) code & 0xFF;

  sendDataLowLevel(wsConnectionDesc, WS_OPCODE_DISCONNECT, true, masked, help, 2);

  if (wsConnectionDesc->lastMessage.data && wsConnectionDesc->lastMessage.complete)
    refcnt_unref(wsConnectionDesc->lastMessage.data);
  else
    free(wsConnectionDesc->lastMessage.data);

  wsConnectionDesc->lastMessage.data = NULL;
  wsConnectionDesc->lastMessage.len = 0;
  wsConnectionDesc->lastMessage.complete = 0;

  switch (wsConnectionDesc->wsType) {
  case WS_TYPE_SERVER:
    socketServer_closeConnection(wsConnectionDesc->socketClientDesc);
    break;

  case WS_TYPE_CLIENT:
    socketClient_closeConnection(wsConnectionDesc->socketClientDesc);
    break;
  }
}

/**
 * \brief returns the user data of the given client
 *
 * \param *wsConnectionDesc Pointer to the websocket client descriptor
 *
 * \ŗeturn The user data of the given connection
 *
 */
void *
websocket_getConnectionUserData(struct websocket_connection_desc *wsConnectionDesc)
{
  return wsConnectionDesc->connectionUserData;
}

/**
 * \brief opens a websocket server
 *
 * \param *wsInit Pointer to the init struct
 * \param *websocketUserData userData for the socket
 *
 * \return The websocket descriptor or NULL in case of error
 *         it can be passed to websocket_ref if it is used
 *         at more places
 */
struct websocket_server_desc *
websocketServer_open(struct websocket_server_init *wsInit, void *websocketUserData)
{
  struct socket_server_init socketInit;
  struct websocket_server_desc *wsDesc;

  wsDesc = refcnt_allocate(sizeof(struct websocket_server_desc), NULL);
  if (!wsDesc) {
    ezwebsocket_log(EZLOG_ERROR, "refcnt_allocate failed\n");
    return NULL;
  }
  memset(wsDesc, 0, sizeof(struct websocket_server_desc));

  wsDesc->ws_onOpen = wsInit->ws_onOpen;
  wsDesc->ws_onClose = wsInit->ws_onClose;
  wsDesc->ws_onCloseLegacy = NULL;
  wsDesc->ws_onMessage = wsInit->ws_onMessage;
  wsDesc->wsSocketUserData = websocketUserData;

  socketInit.address = wsInit->address;
  socketInit.port = wsInit->port;
  socketInit.socket_onOpen = websocketServer_onOpen;
  socketInit.socket_onClose = websocket_onClose;
  socketInit.socket_onIdle = websocket_onIdle;
  socketInit.socket_onMessage = websocket_onMessage;

  wsDesc->socketDesc = socketServer_open(&socketInit, wsDesc);
  if (!wsDesc->socketDesc) {
    ezwebsocket_log(EZLOG_ERROR, "socketServer_open failed\n");
    refcnt_unref(wsDesc);
    return NULL;
  }

  return wsDesc;
}

/**
 * \brief closes the given websocket server
 *        and decreases the reference counter of wsDesc by 1
 *
 * \param *wsDesc Pointer to the websocket descriptor
 *
 */
void
websocketServer_close(struct websocket_server_desc *wsDesc)
{
  socketServer_close(wsDesc->socketDesc);
  refcnt_unref(wsDesc);
}

/**
 * \brief opens a websocket client connection
 *
 * \param wsInit Pointer to the init struct
 * \param websocketUserData UserData for the socket
 *
 * \return The websocket client descriptor or NULL in case of error
 *         it can be passed to websocket_ref if it is used
 *         at more places
 */
struct websocket_connection_desc *
websocketClient_open(struct websocket_client_init *wsInit, void *websocketUserData)
{
  struct socket_client_init socketInit = { 0 };
  struct websocket_connection_desc *wsConnection;

  if (!wsInit || !validClientRequestPart(wsInit->address) ||
      !validClientRequestPart(wsInit->port) || !validClientRequestPart(wsInit->endpoint)) {
    ezwebsocket_log(EZLOG_ERROR, "invalid WebSocket client request field\n");
    return NULL;
  }

  wsConnection = refcnt_allocate(sizeof(struct websocket_connection_desc), freeConnection);
  if (wsConnection == NULL) {
    goto ERROR;
  }
  memset(wsConnection, 0, sizeof(struct websocket_connection_desc));

  wsConnection->wsType = WS_TYPE_CLIENT;
  wsConnection->state = WS_STATE_HANDSHAKE;
  wsConnection->lastMessage.firstReceived = false;
  wsConnection->lastMessage.complete = false;
  wsConnection->lastMessage.data = NULL;
  wsConnection->lastMessage.len = 0;
  wsConnection->timeout.tv_nsec = 0;
  wsConnection->timeout.tv_sec = 0;
  wsConnection->connectionUserData = NULL;
  wsConnection->wsDesc.wsClientDesc = malloc(sizeof(struct websocket_client_desc));
  if (wsConnection->wsDesc.wsClientDesc == NULL) {
    goto ERROR;
  }
  memset(wsConnection->wsDesc.wsClientDesc, 0, sizeof(struct websocket_client_desc));

  wsConnection->wsDesc.wsClientDesc->wsUserData = websocketUserData;
  wsConnection->wsDesc.wsClientDesc->ws_onOpen = wsInit->ws_onOpen;
  wsConnection->wsDesc.wsClientDesc->ws_onClose = wsInit->ws_onClose;
  wsConnection->wsDesc.wsClientDesc->ws_onMessage = wsInit->ws_onMessage;
  wsConnection->wsDesc.wsClientDesc->connection = wsConnection;

  wsConnection->socketClientDesc = NULL;
  wsConnection->wsDesc.wsClientDesc->address = strdup(wsInit->address);
  if (wsConnection->wsDesc.wsClientDesc->address == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "strdup failed\n");
    goto ERROR;
  }
  wsConnection->wsDesc.wsClientDesc->port = strdup(wsInit->port);
  if (wsConnection->wsDesc.wsClientDesc->port == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "strdup failed\n");
    goto ERROR;
  }
  wsConnection->wsDesc.wsClientDesc->endpoint = strdup(wsInit->endpoint);
  if (wsConnection->wsDesc.wsClientDesc->endpoint == NULL) {
    ezwebsocket_log(EZLOG_ERROR, "strdup failed\n");
    goto ERROR;
  }

  uint32_t tempPort = strtoul(wsInit->port, NULL, 10);
  if ((tempPort == 0) || (tempPort > USHRT_MAX)) {
    ezwebsocket_log(EZLOG_ERROR, "port outside allowed range\n");
    goto ERROR;
  }

  socketInit.port = tempPort;
  socketInit.keepalive = wsInit->keepalive;
  socketInit.keep_idle_sec = wsInit->keep_idle_sec;
  socketInit.keep_cnt = wsInit->keep_cnt;
  socketInit.keep_intvl = wsInit->keep_intvl;
  socketInit.secure = wsInit->secure;
  socketInit.address = wsInit->address;
  socketInit.socket_onOpen = websocketClient_onOpen;
  socketInit.socket_onClose = websocket_onClose;
  socketInit.socket_onIdle = websocket_onIdle;
  socketInit.socket_onMessage = websocket_onMessage;

  wsConnection->socketClientDesc = socketClient_open(&socketInit, wsConnection);
  if (!wsConnection->socketClientDesc) {
    ezwebsocket_log(EZLOG_WARNING, "socketClient_open failed\n");
    goto ERROR;
  }

  websocket_ref(wsConnection);
  socketClient_start(wsConnection->socketClientDesc);

  struct timespec timeoutStartTime;
  struct timespec currentTime;

  clock_gettime(CLOCK_MONOTONIC, &timeoutStartTime);

  while (wsConnection->state == WS_STATE_HANDSHAKE) {
    clock_gettime(CLOCK_MONOTONIC, &currentTime);
    if (currentTime.tv_sec > timeoutStartTime.tv_sec + MESSAGE_TIMEOUT_S)
      goto ERROR;
    usleep(10000);
  }

  if (wsConnection->state != WS_STATE_CONNECTED)
    goto ERROR;

  return wsConnection;

ERROR:
  websocketClient_close(wsConnection, WS_CLOSE_CODE_PROTOCOL_ERROR);
  return NULL;
}

/**
 * \brief Closes a websocket client
 *        and decreases the reference counter of wsConnectionDesc by 1
 *
 * \param *wsConnectionDesc Pointer to the websocket client descriptor
 * \param code The closing code
 */
void
websocketClient_close(struct websocket_connection_desc *wsConnectionDesc, enum ws_close_code code)
{
  if (wsConnectionDesc == NULL)
    return;

  if (wsConnectionDesc->socketClientDesc)
    websocket_closeConnection(wsConnectionDesc, code);
  else
    wsConnectionDesc->state = WS_STATE_CLOSED;
  refcnt_unref(wsConnectionDesc);
}

/**
 * \brief Returns if the client is still connected
 *
 * \param *wsConnectionDesc Pointer to the websocket connection descriptor
 *
 * \return True => connected else false
 */
bool
websocketConnection_isConnected(struct websocket_connection_desc *wsConnectionDesc)
{
  if (!wsConnectionDesc)
    return false;

  ezwebsocket_log(EZLOG_INFO, "connection state: %d\n", wsConnectionDesc->state);
  return (wsConnectionDesc->state != WS_STATE_CLOSED);
}

/**
 * \brief increments the reference count of the given object
 *
 * \param *ptr Poiner to the object
 */
void
websocket_ref(void *ptr)
{
  refcnt_ref(ptr);
}

/**
 * \brief Decrements the reference count of the given object and frees it if necessary
 *
 * \param *ptr Pointer to the object
 */
void
websocket_unref(void *ptr)
{
  refcnt_unref(ptr);
}

/* ------------------------------ LEGACY FUNCTIONS ------------------------------ */

/**
 * \brief Opens a websocket server
 *
 * \param wsInit Pointer to the init struct
 * \param websocketUserData UserData for the socket
 *
 * \return The websocket descriptor or NULL in case of error
 *
 * \note LEGACY!!! This function is for backward compatibility
 *       it should not be used anymore but will not be
 *       removed unless there's a good reason
 */
void *
websocket_open(struct websocket_init *wsInit, void *websocketUserData)
{
  struct socket_server_init socketInit;
  struct websocket_server_desc *wsDesc;

  wsDesc = refcnt_allocate(sizeof(struct websocket_server_desc), NULL);
  if (!wsDesc) {
    ezwebsocket_log(EZLOG_ERROR, "refcnt_allocate failed\n");
    return NULL;
  }
  memset(wsDesc, 0, sizeof(struct websocket_server_desc));

  wsDesc->ws_onOpenLegacy = (void *(*) (struct websocket_server_desc *,
                                        struct websocket_connection_desc *) ) wsInit->ws_onOpen;
  wsDesc->ws_onCloseLegacy = (void (*)(void *, struct websocket_connection_desc *,
                                       void *)) wsInit->ws_onClose;
  wsDesc->ws_onClose = NULL;
  wsDesc->ws_onMessage = (void (*)(void *, struct websocket_connection_desc *, void *,
                                   enum ws_data_type, void *, size_t)) wsInit->ws_onMessage;
  wsDesc->wsSocketUserData = websocketUserData;

  socketInit.address = wsInit->address;
  socketInit.port = wsInit->port;
  socketInit.socket_onOpen = websocketServer_onOpen;
  socketInit.socket_onClose = websocket_onClose;
  socketInit.socket_onIdle = websocket_onIdle;
  socketInit.socket_onMessage = websocket_onMessage;

  wsDesc->socketDesc = socketServer_open(&socketInit, wsDesc);
  if (!wsDesc->socketDesc) {
    ezwebsocket_log(EZLOG_ERROR, "socketServer_open failed\n");
    refcnt_unref(wsDesc);
    return NULL;
  }

  return wsDesc;
}

/**
 * \brief Closes the given websocket server
 *
 * \param *wsDesc Pointer to the websocket descriptor
 *
 * \note LEGACY!!! This function is for backward compatibility
 *       it should not be used anymore but will not be
 *       removed unless there's a good reason
 */
void
websocket_close(void *wsDesc)
{
  websocketServer_close(wsDesc);
}

/**
 * \brief Returns the user data of the given connection
 *
 * \param *wsClientDesc Pointer to the websocket client descriptor
 *
 * \note LEGACY!!! This function is for backward compatibility
 *       it should not be used anymore but will not be
 *       removed unless there's a good reason
 */
void *
websocket_getClientUserData(void *wsClientDesc)
{
  return websocket_getConnectionUserData(wsClientDesc);
}

void
websocket_init()
{
#ifdef HAVE_OPENSSL
  SSL_library_init();
  SSL_load_error_strings();
#endif
}
