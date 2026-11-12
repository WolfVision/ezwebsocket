#include "dyn_buffer.h"
#include "utf8.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int
test_dyn_buffer(void)
{
  struct dyn_buffer buffer;

  dynBuffer_init(&buffer);
  if (dynBuffer_increase_to(&buffer, 8) != 0)
    return 1;

  memcpy(DYNBUFFER_WRITE_POS(&buffer), "abcdef", 6);
  DYNBUFFER_INCREASE_WRITE_POS(&buffer, 6);
  if (dynBuffer_increase_to(&buffer, 4) != 0 || DYNBUFFER_BYTES_FREE(&buffer) < 4)
    return 1;

  if (dynBuffer_removeLeadingBytes(&buffer, 2) != 0 || DYNBUFFER_SIZE(&buffer) != 4 ||
      memcmp(DYNBUFFER_BUFFER(&buffer), "cdef", 4) != 0)
    return 1;

  if (dynBuffer_increase_to(&buffer, SIZE_MAX) == 0)
    return 1;

  if (dynBuffer_removeLeadingBytes(&buffer, 4) != 0 || buffer.buffer != NULL || buffer.size != 0)
    return 1;

  return 0;
}

static int
test_utf8_validation(void)
{
  unsigned long handle = 0;
  char euro_sign[] = "\xe2\x82\xac";
  char overlong[] = "\xc0\x80";

  if (utf8_validate(euro_sign, 1, &handle) != UTF8_STATE_BUSY ||
      utf8_validate(&euro_sign[1], 2, &handle) != UTF8_STATE_OK)
    return 1;

  handle = 0;
  if (utf8_validate(overlong, sizeof(overlong) - 1, &handle) != UTF8_STATE_FAIL)
    return 1;

  return 0;
}

int
main(void)
{
  if (test_dyn_buffer() != 0) {
    fprintf(stderr, "dynamic buffer unit test failed\n");
    return 1;
  }

  if (test_utf8_validation() != 0) {
    fprintf(stderr, "UTF-8 unit test failed\n");
    return 1;
  }

  return 0;
}