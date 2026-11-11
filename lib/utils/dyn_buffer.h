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

#ifndef DYN_BUFFER_H_
#define DYN_BUFFER_H_

#include <stddef.h>

#ifndef MAX_WEBSOCKET_PAYLOAD_LENGTH
#define MAX_WEBSOCKET_PAYLOAD_LENGTH (4 * 1024 * 1024)
#endif

//! structure that contains all necessary information of the dynamic buffer
struct dyn_buffer {
  //! pointer to the buffer that holds the data
  char *buffer;
  //! the number of used bytes
  size_t used;
  //! the size of the buffer
  size_t size;
};

//! The minimum allocated amount of bytes
#define DYNBUFFER_INCREASE_STEPS                 1024

//! returns the write position of the dynbuffer
#define DYNBUFFER_WRITE_POS(buf)                 (&((buf)->buffer[(buf)->used]))
//! increases the write position of the dynbuffer
#define DYNBUFFER_INCREASE_WRITE_POS(buf, bytes) ((buf)->used += bytes)
//! returns the remaining space of the dynbuffer
#define DYNBUFFER_BYTES_FREE(buf)                ((buf)->size - (buf)->used)
//! returns the current size of the dynbuffer
#define DYNBUFFER_SIZE(buf)                      ((buf)->used)
//! returns the base address of the buffer
#define DYNBUFFER_BUFFER(buf)                    ((buf)->buffer)

void
dynBuffer_init(struct dyn_buffer *buffer);
int
dynBuffer_increase_to(struct dyn_buffer *buffer, size_t numFreeBytes);
int
dynBuffer_removeLeadingBytes(struct dyn_buffer *buffer, size_t count);
int
dynBuffer_delete(struct dyn_buffer *buffer);

#endif /* DYN_BUFFER_H_ */
