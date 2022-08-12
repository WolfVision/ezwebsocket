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
#include <ezwebsocket.h>
#include <ezwebsocket_log.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
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

//! if payload length in the websocket header is smaller or equal than this
//! the extended payload is not used
#define MAX_DEFAULT_PAYLOAD_LENGTH    125
//! value of the websocket payload length if the extended 16-bit length is used
#define EXTENDED_16BIT_PAYLOAD_LENGTH 126
//! value of the websocket payload length if the extended 64-bit length is used
#define EXTENDED_64BIT_PAYLOAD_LENGTH 127

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
#define WS_HS_KEY_ID  "Sec-WebSocket-Key:"
//! websocket handshake key identifier length
#define WS_HS_KEY_LEN 25

/**
 * \brief Parses the http header and extracts the Sec-WebSocket-Key
 *
 * \param *wsHeader Pointer to the string with the header
 * \param len Length of the header
 * \param[out] *key Pointer to where the key should be stored (should be at least WS_HS_KEY_LEN big)
 *
 * \return 0 if successful else -1
 *
 */
static int
parseHttpHeader(const char *wsHeader, size_t len, char *key)
{
  const char *cpnt;
  int i;

  cpnt = strnstr((char *) wsHeader, WS_HS_KEY_ID, len);
  if (!cpnt) {
    ezwebsocket_log(EZLOG_WARNING, "%s() couldn't find key\n", __func__);
    return -1;
  }

  cpnt += strlen(WS_HS_KEY_ID);

  while (!isgraph(*cpnt)) {
    cpnt++;
  }

  for (i = 0; (i < WS_HS_KEY_LEN - 1) && isgraph(cpnt[i]) && ((size_t) (&cpnt[i] - wsHeader) < len);
       i++) {
    key[i] = cpnt[i];
  }

  if (i < WS_HS_KEY_LEN - 1)
    return -1;

  key[i] = '\0';

  ezwebsocket_log(EZLOG_DEBUG, "%s() key:%s\n", __func__, key);
  return 0;
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
    ezwebsocket_log(EZLOG_WARNING, "problem with the handshake reply key (buffer to small)\n");
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
 * \return True => handshake correct else false
 */
static bool
checkWsHandshakeReply(struct websocket_connection_desc *wsConnectionDesc, char *header, size_t *len)
{
  if (wsConnectionDesc->wsType == WS_TYPE_SERVER)
    return false;

  struct websocket_client_desc *wsDesc = wsConnectionDesc->wsDesc.wsClientDesc;

  char *cpnt;
  unsigned long i;
  char key[30];
  char *acceptString = NULL;
  bool retVal = false;

  ezwebsocket_log(EZLOG_DEBUG, "%s() HS_REPLY_ID: %.*s\n", __func__, (int) *len, header);
  cpnt = strnstr(header, WS_HS_REPLY_ID, *len);
  if (!cpnt) {
    ezwebsocket_log(EZLOG_WARNING, "%s() couldn't find key\n", __func__);
    return false;
  }

  cpnt += strlen(WS_HS_REPLY_ID);

  while (!isgraph(*cpnt)) {
    cpnt++;

    if ((size_t) (cpnt - header) >= *len)
      return false;
  }

  for (i = 0; (i < sizeof(key) - 1) && isgraph(cpnt[i]) && ((size_t) (&cpnt[i] - header) < *len);
       i++) {
    key[i] = cpnt[i];
  }

  key[i] = '\0';

  cpnt = strnstr(header, "\r\n\r\n", *len);
  if (cpnt == NULL)
    return false;
  cpnt += strlen("\r\n\r\n");

  *len = (uintptr_t) cpnt - (uintptr_t) header;

  acceptString = calculateSecWebSocketAccept(wsDesc->wsKey);
  if (acceptString == NULL) {
    ezwebsocket_log(EZLOG_WARNING, "calculateSecWebSocketAccept failed\n");
    return false;
  }

  retVal = (strcmp(key, acceptString) == 0);

  free(acceptString);
  return retVal;
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
  unsigned long i;
  char *requestHeader = NULL;
  bool success = false;
  struct websocket_client_desc *wsDesc = wsConnectionDesc->wsDesc.wsClientDesc;

  for (i = 0; i < sizeof(wsKeyBytes); i++) {
    wsKeyBytes[i] = rand();
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
    ezwebsocket_log(EZLOG_WARNING, "asprintf failed\n");
    goto EXIT;
  }

  if (socketClient_send(wsConnectionDesc->socketClientDesc, requestHeader, strlen(requestHeader)) ==
      -1) {
    ezwebsocket_log(EZLOG_WARNING, "socketClient_send failed\n");
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

// Frame format of a websocket:
//​​
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
static void __attribute__((unused)) printWsHeader(const struct ws_header *header)
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
  header->fin = (data[0] & 0x80) ? true : false;
  header->opcode = data[0] & 0x0F;
  if (data[0] & 0x70) // reserved bits must be 0
  {
    ezwebsocket_log(EZLOG_WARNING, "reserved bits must be 0\n");
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
    ezwebsocket_log(EZLOG_WARNING, "opcode unknown (%d)\n", header->opcode);
    return -1;
  }

  header->masked = (data[1] & 0x80) ? true : false;
  size_t i, lengthNumBytes;

  if (len < 2) {
    return 0;
  }

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
    header->payloadLength <<= 8;
    header->payloadLength |= data[2 + i];
  }

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
      buffer[cnt] = (len >> (i * 8)) & 0xFF;
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
  int headerLength;
  unsigned char *sendBuffer;
  int rc = -1;
  unsigned long mask = 0;

  if (wsConnectionDesc->state == WS_STATE_CLOSED)
    return -1;

  if (masked) {
    mask = (rand() << 16) | (rand() & 0x0000FFFF);
  }

  headerLength = createWebsocketHeader(header, opcode, fin, masked, mask, len);

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
    ezwebsocket_log(EZLOG_WARNING, "last message not finished\n");
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }

  if (header->payloadLength) // it's allowed to send frames with payload length = 0
  {
    if (header->fin)
      wsConnectionDesc->lastMessage.data = refcnt_allocate(header->payloadLength, NULL);
    else
      wsConnectionDesc->lastMessage.data = malloc(header->payloadLength);
    if (!wsConnectionDesc->lastMessage.data) {
      ezwebsocket_log(EZLOG_WARNING, "refcnt_allocate failed dropping message\n");
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
      ezwebsocket_log(EZLOG_WARNING, "no valid utf8 string closing connection\n");
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
    ezwebsocket_log(EZLOG_WARNING, "missing last message closing connection\n");
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }

  if ((wsConnectionDesc->wsType != WS_TYPE_SERVER) == header->masked) {
    ezwebsocket_log(EZLOG_WARNING, "mask bit wrong\n");
    websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
    return WS_MSG_STATE_ERROR;
  }

  if (wsConnectionDesc->lastMessage.len +
      header->payloadLength) // it's allowed to send frames with payload length = 0
  {
    if (header->fin) {
      temp = refcnt_allocate(wsConnectionDesc->lastMessage.len + header->payloadLength, NULL);
      if (!temp) {
        ezwebsocket_log(EZLOG_WARNING, "refcnt_allocate failed dropping message\n");
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
        ezwebsocket_log(EZLOG_WARNING, "realloc failed dropping message\n");
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
      ezwebsocket_log(EZLOG_WARNING, "no valid utf8 string closing connection\n");
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
          ezwebsocket_log(EZLOG_WARNING, "malloc failed dropping message\n");
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
  int rc;
  unsigned long utf8Handle = 0;
  bool masked = (wsConnectionDesc->wsType == WS_TYPE_CLIENT);

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
      if ((header->payloadLength == 2) ||
          utf8_validate((char *) &data[header->payloadStartOffset + 2], header->payloadLength - 2,
                        &utf8Handle)) {
        ezwebsocket_log(EZLOG_INFO, "SEND DISCONNECT\n");
        if (sendDataLowLevel(wsConnectionDesc, WS_OPCODE_DISCONNECT, true, masked,
                             &data[header->payloadStartOffset], header->payloadLength) == 0)
          rc = WS_MSG_STATE_NO_USER_DATA;
        else
          rc = WS_MSG_STATE_ERROR;
        switch (wsConnectionDesc->wsType) {
        case WS_TYPE_SERVER:
          socketServer_closeConnection(wsConnectionDesc->socketClientDesc);
          break;

        case WS_TYPE_CLIENT:
          socketClient_closeConnection(wsConnectionDesc->wsDesc.wsClientDesc->socketDesc);
          break;
        }
      } else {
        websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_INVALID_DATA);
        rc = WS_MSG_STATE_ERROR;
      }
      return rc;
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

  if (len < header->payloadStartOffset + header->payloadLength)
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
    ezwebsocket_log(EZLOG_WARNING, "unknown opcode (%d)\n", header->opcode);
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
    ezwebsocket_log(EZLOG_WARNING, "%s(): wsDesc must not be NULL!\n", __func__);
    return NULL;
  }

  if (socketConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_WARNING, "%s(): socketClientDesc must not be NULL!\n", __func__);
    return NULL;
  }

  refcnt_ref(socketConnectionDesc);
  wsConnectionDesc = refcnt_allocate(sizeof(struct websocket_connection_desc), NULL);
  memset(wsConnectionDesc, 0, sizeof(struct websocket_connection_desc));
  wsConnectionDesc->wsType = WS_TYPE_SERVER;
  wsConnectionDesc->socketClientDesc = socketConnectionDesc;
  wsConnectionDesc->state = WS_STATE_HANDSHAKE;
  wsConnectionDesc->timeout.tv_nsec = 0;
  wsConnectionDesc->timeout.tv_sec = 0;
  wsConnectionDesc->lastMessage.firstReceived = false;
  wsConnectionDesc->lastMessage.data = NULL;
  wsConnectionDesc->lastMessage.len = 0;
  wsConnectionDesc->lastMessage.complete = false;
  wsConnectionDesc->wsDesc.wsServerDesc = wsDesc;

  return wsConnectionDesc;
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
  (void) socketConnectionDesc;

  if (wsConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_WARNING, "%s(): wsConnectionDesc must not be NULL!\n", __func__);
    return;
  }

  if (wsConnectionDesc->lastMessage.data && wsConnectionDesc->lastMessage.complete)
    refcnt_unref(wsConnectionDesc->lastMessage.data);
  else
    free(wsConnectionDesc->lastMessage.data);
  wsConnectionDesc->lastMessage.data = NULL;

  if (wsConnectionDesc->state == WS_STATE_CONNECTED) {
    wsConnectionDesc->state = WS_STATE_CLOSED;

    callOnClose(wsConnectionDesc);
  }

  if (wsConnectionDesc->wsType ==
      WS_TYPE_SERVER) // in client mode the connection descriptor is not allocated
  {
    if (wsConnectionDesc->socketClientDesc)
      refcnt_unref(wsConnectionDesc->socketClientDesc);
    wsConnectionDesc->socketClientDesc = NULL;
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

  char key[WS_HS_KEY_LEN];
  char *replyKey;

  if (wsConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_WARNING, "%s(): wsConnectionDesc must not be NULL!\n", __func__);
    return 0;
  }

  if (socketConnectionDesc == NULL) {
    ezwebsocket_log(EZLOG_WARNING, "%s(): socketConnectionDesc must not be NULL!\n", __func__);
    return 0;
  }

  switch (wsConnectionDesc->state) {
  case WS_STATE_HANDSHAKE:
    switch (wsConnectionDesc->wsType) {
    case WS_TYPE_SERVER:
      if (parseHttpHeader(msg, len, key) == 0) {
        struct websocket_server_desc *wsDesc = socketUserData;

        replyKey = calculateSecWebSocketAccept(key);
        if (replyKey == NULL) {
          ezwebsocket_log(EZLOG_WARNING, "%s(): calculateSecWebSocketAccept failed!\n", __func__);
          return 0;
        }

        ezwebsocket_log(EZLOG_DEBUG, "%s() replyKey:%s\n", __func__, replyKey);

        sendWsHandshakeReply(socketConnectionDesc, replyKey);

        free(replyKey);
        wsConnectionDesc->state = WS_STATE_CONNECTED;
        if (wsDesc->ws_onOpen != NULL)
          wsConnectionDesc->connectionUserData = wsDesc->ws_onOpen(wsDesc->wsSocketUserData, wsDesc,
                                                                   wsConnectionDesc);

        if (wsDesc->ws_onOpenLegacy != NULL)
          wsConnectionDesc->connectionUserData = wsDesc->ws_onOpenLegacy(wsDesc, wsConnectionDesc);
      } else {
        ezwebsocket_log(EZLOG_WARNING, "parseHttpHeader failed\n");
      }
      break;

    case WS_TYPE_CLIENT:
      if (checkWsHandshakeReply(wsConnectionDesc, msg, &len)) {
        struct websocket_client_desc *wsDesc = wsConnectionDesc->wsDesc.wsClientDesc;

        wsConnectionDesc->state = WS_STATE_CONNECTED;

        if (wsDesc->ws_onOpen != NULL)
          wsConnectionDesc->connectionUserData = wsDesc->ws_onOpen(wsDesc->wsUserData,
                                                                   wsConnectionDesc);
        else
          wsConnectionDesc->connectionUserData = NULL;
      } else {
        ezwebsocket_log(EZLOG_WARNING, "checkWsHandshakeReply failed\n");
      }
      break;
    }
    return len;

  case WS_STATE_CONNECTED:
    switch (parseWebsocketHeader(msg, len, &wsHeader)) {
    case -1:
      ezwebsocket_log(EZLOG_WARNING, "couldn't parse header\n");
      websocket_closeConnection(wsConnectionDesc, WS_CLOSE_CODE_PROTOCOL_ERROR);
      return len;

    case 0:
      return 0;
      break;

    case 1:
      break;
    }
    printWsHeader(&wsHeader);

    switch (parseMessage(wsConnectionDesc, msg, len, &wsHeader)) {
    case WS_MSG_STATE_NO_USER_DATA:
      wsConnectionDesc->timeout.tv_nsec = 0;
      wsConnectionDesc->timeout.tv_sec = 0;
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
      if (wsConnectionDesc->timeout.tv_sec == (wsConnectionDesc->timeout.tv_nsec == 0)) {
        wsConnectionDesc->timeout = now;
      } else if (wsConnectionDesc->timeout.tv_sec > now.tv_sec + MESSAGE_TIMEOUT_S) {
        free(wsConnectionDesc->lastMessage.data);
        wsConnectionDesc->lastMessage.data = NULL;
        wsConnectionDesc->lastMessage.len = 0;
        wsConnectionDesc->lastMessage.complete = 0;
        wsConnectionDesc->timeout.tv_sec = 0;
        wsConnectionDesc->timeout.tv_nsec = 0;
        ezwebsocket_log(EZLOG_WARNING, "message timeout");
        return len;
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
      ezwebsocket_log(EZLOG_WARNING, "unexpected return value\n");
      return len;
    }
    break;

  case WS_STATE_CLOSED:
    ezwebsocket_log(EZLOG_WARNING, "websocket closed ignoring message\n");
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
    ezwebsocket_log(EZLOG_WARNING, "unknown data type\n");
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
    ezwebsocket_log(EZLOG_WARNING, "unknown data type\n");
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
    ezwebsocket_log(EZLOG_WARNING, "refcnt_allocate failed\n");
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
  socketInit.socket_onMessage = websocket_onMessage;

  wsDesc->socketDesc = socketServer_open(&socketInit, wsDesc);
  if (!wsDesc->socketDesc) {
    ezwebsocket_log(EZLOG_WARNING, "socketServer_open failed\n");
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
    ezwebsocket_log(EZLOG_WARNING, "strdup failed\n");
    goto ERROR;
  }
  wsConnection->wsDesc.wsClientDesc->port = strdup(wsInit->port);
  if (wsConnection->wsDesc.wsClientDesc->port == NULL) {
    ezwebsocket_log(EZLOG_WARNING, "strdup failed\n");
    goto ERROR;
  }
  wsConnection->wsDesc.wsClientDesc->endpoint = strdup(wsInit->endpoint);
  if (wsConnection->wsDesc.wsClientDesc->endpoint == NULL) {
    ezwebsocket_log(EZLOG_WARNING, "strdup failed\n");
    goto ERROR;
  }

  uint32_t tempPort = strtoul(wsInit->port, NULL, 10);
  if ((tempPort == 0) || (tempPort > USHRT_MAX)) {
    ezwebsocket_log(EZLOG_WARNING, "port outside allowed range\n");
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
  socketInit.socket_onMessage = websocket_onMessage;

  wsConnection->socketClientDesc = socketClient_open(&socketInit, wsConnection);
  if (!wsConnection->socketClientDesc) {
    ezwebsocket_log(EZLOG_WARNING, "socketClient_open failed\n");
    goto ERROR;
  }

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
  freeConnection(wsConnectionDesc);
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
    ezwebsocket_log(EZLOG_WARNING, "refcnt_allocate failed\n");
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
  socketInit.socket_onMessage = websocket_onMessage;

  wsDesc->socketDesc = socketServer_open(&socketInit, wsDesc);
  if (!wsDesc->socketDesc) {
    ezwebsocket_log(EZLOG_WARNING, "socketServer_open failed\n");
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
