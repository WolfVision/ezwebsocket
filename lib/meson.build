
srcs_websocket = [
  'utils/base64.c',
  'utils/dyn_buffer.c',
  'utils/log.c',
  'utils/ref_count.c',
  'utils/stringck.c',
  'utils/utf8.c',
  'utils/host_resolve.c',
  'socket_client/socket_client.c',
  'socket_server/socket_server.c',
  'ezwebsocket.c',
]

inc_websocket = [
  inc_common,
  include_directories('utils'),
  include_directories('socket_client'),
  include_directories('socket_server'),
]

if get_option('openssl').disabled()
  srcs_websocket += 'utils/sha1.c'
endif

deps_websocket = [
  dep_threads,
  dep_ssl,
]

if get_option('syslog').enabled()
  if cc.has_header('syslog.h')
    config_h.set('HAVE_SYSLOG_H', '1')
  endif
endif

libezwebsocket = shared_library(
    'ezwebsocket',
    srcs_websocket,
    include_directories : inc_websocket,
    version : meson.project_version(),
    dependencies: deps_websocket,
    install : true)

dep_libezwebsocket = declare_dependency(
    link_with: libezwebsocket,
    include_directories : inc_websocket,
    )

pkg.generate(libezwebsocket)

