#define _POSIX_C_SOURCE 200809L

#include <ezwebsocket.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef MAX_WEBSOCKET_PAYLOAD_LENGTH
#define MAX_WEBSOCKET_PAYLOAD_LENGTH (4 * 1024 * 1024)
#endif

struct function_state {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  size_t messages_received;
  size_t messages_echoed;
  bool messages_match;
  bool echoes_succeeded;
};

static void *
server_on_open(void *websocket_user_data, struct websocket_server_desc *server,
               struct websocket_connection_desc *connection)
{
  (void) websocket_user_data;
  (void) server;
  (void) connection;
  return NULL;
}

static void
server_on_message(void *websocket_user_data, struct websocket_connection_desc *connection,
                  void *connection_user_data, enum ws_data_type data_type, void *message,
                  size_t length)
{
  struct function_state *state = websocket_user_data;
  int send_result;

  (void) connection_user_data;
  send_result = websocket_sendData(connection, data_type, message, length);

  pthread_mutex_lock(&state->mutex);
  state->messages_echoed++;
  state->echoes_succeeded = state->echoes_succeeded && send_result == 0;
  pthread_cond_broadcast(&state->condition);
  pthread_mutex_unlock(&state->mutex);
}

static void *
client_on_open(void *websocket_user_data, struct websocket_connection_desc *connection)
{
  (void) websocket_user_data;
  (void) connection;
  return NULL;
}

static void
client_on_message(void *websocket_user_data, struct websocket_connection_desc *connection,
                  void *connection_user_data, enum ws_data_type data_type, void *message,
                  size_t length)
{
  static const char expected[] = "loopback echo";
  static const char fragmented_expected[] = "fragmented echo";
  struct function_state *state = websocket_user_data;
  bool message_matches;

  (void) connection;
  (void) connection_user_data;

  pthread_mutex_lock(&state->mutex);
  if (state->messages_received == 0) {
    message_matches = data_type == WS_DATA_TYPE_TEXT && length == sizeof(expected) - 1 &&
                      memcmp(message, expected, sizeof(expected) - 1) == 0;
  } else if (state->messages_received == 1) {
    message_matches = data_type == WS_DATA_TYPE_TEXT &&
                      length == sizeof(fragmented_expected) - 1 &&
                      memcmp(message, fragmented_expected, sizeof(fragmented_expected) - 1) ==
                        0;
  } else {
    message_matches = false;
  }
  state->messages_match = state->messages_match && message_matches;
  state->messages_received++;
  pthread_cond_broadcast(&state->condition);
  pthread_mutex_unlock(&state->mutex);
}

static int
get_ephemeral_port(char *port, size_t port_size)
{
  struct sockaddr_in address = { 0 };
  socklen_t address_length = sizeof(address);
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (socket_fd < 0)
    return -1;

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(socket_fd, (struct sockaddr *) &address, sizeof(address)) != 0 ||
      getsockname(socket_fd, (struct sockaddr *) &address, &address_length) != 0) {
    close(socket_fd);
    return -1;
  }

  close(socket_fd);
  return snprintf(port, port_size, "%u", (unsigned int) ntohs(address.sin_port)) > 0 ? 0 : -1;
}

static int
send_all(int socket_fd, const void *data, size_t length)
{
  const unsigned char *position = data;

  while (length) {
    ssize_t sent = send(socket_fd, position, length, 0);
    if (sent <= 0)
      return -1;
    position += sent;
    length -= (size_t) sent;
  }

  return 0;
}

static int
receive_all(int socket_fd, void *data, size_t length)
{
  unsigned char *position = data;

  while (length) {
    ssize_t received = recv(socket_fd, position, length, 0);
    if (received <= 0)
      return -1;
    position += received;
    length -= (size_t) received;
  }

  return 0;
}

static int
test_oversized_incoming_frame(const char *port)
{
  static const char request[] =
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";
  struct sockaddr_in address = { 0 };
  struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
  unsigned char frame[14] = { 0x82, 0xff };
  unsigned char close_frame[4];
  uint64_t payload_length = (uint64_t) MAX_WEBSOCKET_PAYLOAD_LENGTH + 1;
  char response[1024];
  size_t response_length = 0;
  int socket_fd;
  int i;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0)
    return -1;

  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons((unsigned short) strtoul(port, NULL, 10));
  if (connect(socket_fd, (struct sockaddr *) &address, sizeof(address)) != 0 ||
      send_all(socket_fd, request, sizeof(request) - 1) != 0) {
    close(socket_fd);
    return -1;
  }

  while (response_length < sizeof(response) - 1) {
    ssize_t received = recv(socket_fd, &response[response_length],
                            sizeof(response) - 1 - response_length, 0);
    if (received <= 0) {
      close(socket_fd);
      return -1;
    }
    response_length += (size_t) received;
    response[response_length] = '\0';
    if (strstr(response, "\r\n\r\n"))
      break;
  }
  if (response_length == sizeof(response) - 1 || !strstr(response, "101 Switching Protocols")) {
    close(socket_fd);
    return -1;
  }

  for (i = 0; i < 8; i++)
    frame[2 + i] = (unsigned char) (payload_length >> (56 - 8 * i));
  frame[10] = 0x12;
  frame[11] = 0x34;
  frame[12] = 0x56;
  frame[13] = 0x78;
  if (send_all(socket_fd, frame, sizeof(frame)) != 0 ||
      receive_all(socket_fd, close_frame, sizeof(close_frame)) != 0) {
    close(socket_fd);
    return -1;
  }

  close(socket_fd);
  return close_frame[0] == 0x88 && close_frame[1] == 2 && close_frame[2] == 0x03 &&
           close_frame[3] == 0xf1
           ? 0
           : -1;
}

int
main(void)
{
  static const char message[] = "loopback echo";
  struct function_state state = { 0 };
  struct websocket_server_init server_init = { 0 };
  struct websocket_client_init client_init = { 0 };
  struct websocket_server_desc *server = NULL;
  struct websocket_connection_desc *client = NULL;
  struct timespec deadline;
  char port[6];
  bool success = false;
  int wait_result = 0;

  state.messages_match = true;
  state.echoes_succeeded = true;
  if (pthread_mutex_init(&state.mutex, NULL) != 0 ||
      pthread_cond_init(&state.condition, NULL) != 0 ||
      get_ephemeral_port(port, sizeof(port)) != 0) {
    fprintf(stderr, "failed to initialize loopback test\n");
    return 1;
  }

  server_init.address = "127.0.0.1";
  server_init.port = port;
  server_init.ws_onOpen = server_on_open;
  server_init.ws_onMessage = server_on_message;
  server = websocketServer_open(&server_init, &state);
  if (server == NULL) {
    fprintf(stderr, "failed to open loopback server\n");
    goto cleanup;
  }

  if (test_oversized_incoming_frame(port) != 0) {
    fprintf(stderr, "server did not reject an oversized incoming frame with close code 1009\n");
    goto cleanup;
  }

  client_init.address = "127.0.0.1";
  client_init.port = port;
  client_init.endpoint = "/";
  client_init.ws_onOpen = client_on_open;
  client_init.ws_onMessage = client_on_message;
  client = websocketClient_open(&client_init, &state);
  if (client == NULL) {
    fprintf(stderr, "failed to connect loopback client\n");
    goto cleanup;
  }

  if (websocket_sendData(client, WS_DATA_TYPE_TEXT, "x",
                         (size_t) MAX_WEBSOCKET_PAYLOAD_LENGTH + 1) == 0) {
    fprintf(stderr, "oversized outgoing message was accepted\n");
    goto cleanup;
  }

  if (websocket_sendData(client, WS_DATA_TYPE_TEXT, message, sizeof(message) - 1) != 0) {
    fprintf(stderr, "failed to send loopback message\n");
    goto cleanup;
  }

  if (websocket_sendDataFragmentedStart(client, WS_DATA_TYPE_TEXT, "fragmented ", 11) != 0 ||
      websocket_sendDataFragmentedCont(client, true, "echo", 4) != 0) {
    fprintf(stderr, "failed to send fragmented loopback message\n");
    goto cleanup;
  }

  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 10;
  pthread_mutex_lock(&state.mutex);
  while ((state.messages_received < 2 || state.messages_echoed < 2) && wait_result == 0)
    wait_result = pthread_cond_timedwait(&state.condition, &state.mutex, &deadline);
  success = wait_result == 0 && state.messages_match && state.echoes_succeeded;
  pthread_mutex_unlock(&state.mutex);

  if (!success)
    fprintf(stderr, "loopback echo, fragmentation, or payload-limit test failed\n");

cleanup:
  if (client != NULL)
    websocketClient_close(client, WS_CLOSE_CODE_NORMAL);
  if (server != NULL)
    websocketServer_close(server);
  pthread_cond_destroy(&state.condition);
  pthread_mutex_destroy(&state.mutex);
  return success ? 0 : 1;
}