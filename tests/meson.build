test_c_args = [
  '-DMAX_WEBSOCKET_PAYLOAD_LENGTH=' + get_option('max_websocket_payload_length').to_string(),
]

unit_test = executable(
  'unit_test',
  'unit_test.c',
  c_args: test_c_args,
  dependencies: dep_libezwebsocket,
  include_directories: include_directories('../lib/utils'),
)
test('unit', unit_test)

function_test = executable(
  'function_test',
  'function_test.c',
  c_args: test_c_args,
  dependencies: dep_libezwebsocket,
)
test('function', function_test, timeout: 30)