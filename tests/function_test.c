#define _POSIX_C_SOURCE 200809L

#include <ezwebsocket.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/select.h>
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
  bool slow_send_mode;
  bool slow_send_finished;
  int slow_send_result;
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
  bool slow_send_mode;

  (void) connection_user_data;

  pthread_mutex_lock(&state->mutex);
  slow_send_mode = state->slow_send_mode;
  pthread_mutex_unlock(&state->mutex);
  if (slow_send_mode) {
    send_result = websocket_sendData(connection, data_type, message, length);
    pthread_mutex_lock(&state->mutex);
    state->slow_send_result = send_result;
    state->slow_send_finished = true;
    pthread_cond_broadcast(&state->condition);
    pthread_mutex_unlock(&state->mutex);
    return;
  }

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
test_listener_descriptor_limit(void)
{
  struct websocket_server_init server_init = { 0 };
  struct websocket_server_desc *server;
  int descriptors[FD_SETSIZE + 1];
  size_t descriptor_count = 0;
  int descriptor;
  size_t i;
  struct rlimit descriptor_limit;

  if (getrlimit(RLIMIT_NOFILE, &descriptor_limit) != 0)
    return 1;
  if (descriptor_limit.rlim_cur <= FD_SETSIZE) {
    if (descriptor_limit.rlim_max <= FD_SETSIZE) {
      fprintf(stderr, "skipping FD_SETSIZE listener test: hard descriptor limit is too low\n");
      return 0;
    }
    descriptor_limit.rlim_cur = FD_SETSIZE + 1;
    if (setrlimit(RLIMIT_NOFILE, &descriptor_limit) != 0)
      return 1;
  }

  while (descriptor_count < sizeof(descriptors) / sizeof(descriptors[0])) {
    descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0)
      break;
    descriptors[descriptor_count++] = descriptor;
    if (descriptor >= FD_SETSIZE)
      break;
  }

  if (!descriptor_count || descriptors[descriptor_count - 1] < FD_SETSIZE) {
    for (i = 0; i < descriptor_count; i++)
      close(descriptors[i]);
    fprintf(stderr, "unable to exercise FD_SETSIZE listener guard\n");
    return 1;
  }

  server_init.address = "127.0.0.1";
  server_init.port = "0";
  server_init.ws_onOpen = server_on_open;
  server_init.ws_onMessage = server_on_message;
  server = websocketServer_open(&server_init, NULL);

  for (i = 0; i < descriptor_count; i++)
    close(descriptors[i]);

  if (server != NULL) {
    websocketServer_close(server);
    fprintf(stderr, "server opened with listener fd outside FD_SETSIZE\n");
    return 1;
  }

  return 0;
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
test_handshake_response(const char *port, const char *request, const char *status,
                        bool split_request)
{
  struct sockaddr_in address = { 0 };
  struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
  struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000000 };
  char response[1024];
  size_t response_length = 0;
  size_t request_length = strlen(request);
  int socket_fd;
  char byte;
  bool rejected = strncmp(status, "HTTP/1.1 400", 12) == 0;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0)
    return -1;

  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons((unsigned short) strtoul(port, NULL, 10));
  if (connect(socket_fd, (struct sockaddr *) &address, sizeof(address)) != 0) {
    close(socket_fd);
    return -1;
  }

  if (split_request) {
    size_t first_part = request_length / 2;
    if (send_all(socket_fd, request, first_part) != 0) {
      close(socket_fd);
      return -1;
    }
    nanosleep(&pause, NULL);
    if (send_all(socket_fd, request + first_part, request_length - first_part) != 0) {
      close(socket_fd);
      return -1;
    }
  } else if (send_all(socket_fd, request, request_length) != 0) {
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

  if (response_length == sizeof(response) - 1 || strncmp(response, status, strlen(status)) != 0) {
    close(socket_fd);
    return -1;
  }

  if (rejected && recv(socket_fd, &byte, sizeof(byte), 0) != 0) {
    close(socket_fd);
    return -1;
  }

  close(socket_fd);
  return 0;
}

static int
test_http_handshake_validation(const char *port)
{
  static const char invalid_method[] =
    "POST / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n";
  static const char missing_upgrade[] =
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n";
  static const char wrong_version[] =
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 12\r\n\r\n";
  static const char blank_key[] =
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: \r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n";
  static const char partial_key[] =
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-K\r\n\r\n";
  static const char lower_case_split[] =
    "GET / HTTP/1.1\r\n"
    "host: 127.0.0.1\r\n"
    "upgrade: WebSocket\r\n"
    "connection: keep-alive, Upgrade\r\n"
    "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "sec-websocket-version: 13\r\n\r\n";
  static const char bad_request[] = "HTTP/1.1 400";
  static const char switching_protocols[] = "HTTP/1.1 101";

  return test_handshake_response(port, invalid_method, bad_request, false) != 0 ||
           test_handshake_response(port, missing_upgrade, bad_request, false) != 0 ||
           test_handshake_response(port, wrong_version, bad_request, false) != 0 ||
           test_handshake_response(port, blank_key, bad_request, false) != 0 ||
           test_handshake_response(port, partial_key, bad_request, false) != 0 ||
           test_handshake_response(port, lower_case_split, switching_protocols, true) != 0
           ? -1
           : 0;
}

static int
test_client_request_injection_rejected(void)
{
  struct websocket_client_init client_init = { 0 };

  client_init.address = "127.0.0.1";
  client_init.port = "80";
  client_init.endpoint = "/\r\nX-Injected: yes";
  return websocketClient_open(&client_init, NULL) == NULL ? 0 : -1;
}

static int
connect_raw_websocket(const char *port)
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
  char response[1024];
  size_t response_length = 0;
  int receive_buffer = 1024;
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (socket_fd < 0)
    return -1;

  setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
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

  return socket_fd;
}

static int
test_slow_reader_send_timeout(struct function_state *state, const char *port)
{
  const unsigned char mask[4] = { 0x19, 0x2a, 0x3b, 0x4c };
  struct timespec deadline;
  unsigned char *frame;
  uint64_t payload_length = MAX_WEBSOCKET_PAYLOAD_LENGTH;
  size_t frame_length;
  size_t i;
  int socket_fd;
  int wait_result = 0;
  int send_result;

  if (payload_length < 2 * 1024 * 1024)
    return 0;
  if (payload_length > 8 * 1024 * 1024)
    payload_length = 8 * 1024 * 1024;
  frame_length = (size_t) payload_length + 14;
  frame = malloc(frame_length);
  if (frame == NULL)
    return -1;

  frame[0] = 0x82;
  frame[1] = 0xff;
  for (i = 0; i < 8; i++)
    frame[2 + i] = (unsigned char) (payload_length >> (56 - 8 * i));
  memcpy(&frame[10], mask, sizeof(mask));
  for (i = 0; i < (size_t) payload_length; i++)
    frame[14 + i] = (unsigned char) ('A' ^ mask[i % sizeof(mask)]);

  pthread_mutex_lock(&state->mutex);
  state->slow_send_mode = true;
  state->slow_send_finished = false;
  state->slow_send_result = 0;
  pthread_mutex_unlock(&state->mutex);

  socket_fd = connect_raw_websocket(port);
  if (socket_fd < 0 || send_all(socket_fd, frame, frame_length) != 0) {
    if (socket_fd >= 0)
      close(socket_fd);
    free(frame);
    pthread_mutex_lock(&state->mutex);
    state->slow_send_mode = false;
    pthread_mutex_unlock(&state->mutex);
    return -1;
  }
  free(frame);

  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 8;
  pthread_mutex_lock(&state->mutex);
  while (!state->slow_send_finished && wait_result == 0)
    wait_result = pthread_cond_timedwait(&state->condition, &state->mutex, &deadline);
  send_result = state->slow_send_result;
  state->slow_send_mode = false;
  pthread_mutex_unlock(&state->mutex);
  close(socket_fd);

  return wait_result == 0 && send_result != 0 ? 0 : -1;
}

static int
test_oversized_incoming_frame(const char *port)
{
  unsigned char frame[14] = { 0x82, 0xff };
  unsigned char close_frame[4];
  uint64_t payload_length = (uint64_t) MAX_WEBSOCKET_PAYLOAD_LENGTH + 1;
  int socket_fd;
  int i;

  socket_fd = connect_raw_websocket(port);
  if (socket_fd < 0)
    return -1;

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

static int
test_wrongly_masked_close_frame(const char *port)
{
  const unsigned char frame[] = { 0x88, 0x03, 0x03, 0xe8, 'a' };
  unsigned char close_frame[4];
  int socket_fd = connect_raw_websocket(port);

  if (socket_fd < 0)
    return -1;

  if (send_all(socket_fd, frame, sizeof(frame)) != 0 ||
      receive_all(socket_fd, close_frame, sizeof(close_frame)) != 0) {
    close(socket_fd);
    return -1;
  }

  close(socket_fd);
  return close_frame[0] == 0x88 && close_frame[1] == 2 && close_frame[2] == 0x03 &&
           close_frame[3] == 0xea
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

  if (test_listener_descriptor_limit() != 0)
    return 1;
  if (test_client_request_injection_rejected() != 0) {
    fprintf(stderr, "client accepted control characters in a handshake field\n");
    return 1;
  }

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

  if (test_http_handshake_validation(port) != 0) {
    fprintf(stderr, "strict HTTP handshake validation test failed\n");
    goto cleanup;
  }

  if (test_oversized_incoming_frame(port) != 0) {
    fprintf(stderr, "server did not reject an oversized incoming frame with close code 1009\n");
    goto cleanup;
  }

  if (test_wrongly_masked_close_frame(port) != 0) {
    fprintf(stderr, "server did not reject an unmasked client close frame with code 1002\n");
    goto cleanup;
  }

  if (test_slow_reader_send_timeout(&state, port) != 0) {
    fprintf(stderr, "server write did not return after the peer stopped reading\n");
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