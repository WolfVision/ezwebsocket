#define _GNU_SOURCE
#include <assert.h>
#include <ezwebsocket_log.h>
#include <host_resolve.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) ((int) (sizeof(a) / sizeof(a[0])))
#endif

#define ASSERT_CMP(tag, s1, s2)                                                                    \
  {                                                                                                \
    if (s1 && s2) {                                                                                \
      ezwebsocket_log(EZLOG_ERROR, "[%s] %s == %s\n", tag, s1, s2);                                \
      if (strcmp(s1, s2))                                                                          \
        assert(0);                                                                                 \
    } else if (!s1 && !s2)                                                                         \
      ezwebsocket_log(EZLOG_ERROR, "[%s] NULL == NULL\n", tag);                                    \
    else                                                                                           \
      assert(0);                                                                                   \
  }

#define HOST     (1 << 0)
#define SCHEMA   (1 << 1)
#define USER     (1 << 2)
#define PASSWORD (1 << 3)
#define PORT     (1 << 4)
#define PATH     (1 << 5)
#define QUERY    (1 << 6)
#define OPTIONAL (1 << 7)

struct test_dut {
  const char *str;
  int id;
  int require;
  const char *expect;
};

void
test_uri(struct test_dut *test_array, size_t test_array_size,
         void (*cb_url_check)(struct host_resolve_uri *expect, struct host_resolve_uri *found))
{
  int mask_idx = 0;
  int k = 0;
  while (mask_idx < test_array_size) {

    //    ezwebsocket_log(EZLOG_ERROR, "[%d] mask: %s (0x%x)\n", mask_idx,
    //    test_array[mask_idx].str,
    //                    test_array[mask_idx].id);

    for (int i = 0; i < test_array_size; i++) {
      char buf[1023];
      size_t left = sizeof(buf);
      size_t ofs = 0;
      struct test_dut *ignore = NULL;
      struct host_resolve_uri expect_uri = { 0 };

      ignore = &test_array[i];
      //      ezwebsocket_log(EZLOG_ERROR, "\t[%d] ignore: %s (0x%x)\n", i, ignore->str,
      //      ignore->id);

      for (int j = 0; j < test_array_size; j++) {
        struct test_dut *dut = &test_array[j];

        if ((j == i) || (mask_idx == j))
          continue;

        if (test_array[mask_idx].id & dut->require)
          continue;

        if (ignore->id & dut->require)
          continue;

        switch (dut->id) {
        case HOST:
          expect_uri.host = (char *) dut->expect;
          break;
        case SCHEMA:
          expect_uri.schema = (char *) dut->expect;
          break;
        case USER:
          expect_uri.user = (char *) dut->expect;
          break;
        case PASSWORD:
          expect_uri.password = (char *) dut->expect;
          break;
        case PORT:
          if (dut->expect)
            expect_uri.port = atoi(dut->expect);
          break;
        case PATH:
          expect_uri.path = (char *) dut->expect;
          break;
        case QUERY:
          expect_uri.query = (char *) dut->expect;
          break;
        default:
          break;
        }

        //        ezwebsocket_log(EZLOG_ERROR, "\t[%d] concat: %s (0x%x)\n", j,
        //        test_array[j].str,
        //                        test_array[j].id);

        int n = snprintf(buf + ofs, left, "%s", test_array[j].str);
        left -= n;
        ofs += n;
      }

      if (ofs) {
        ezwebsocket_log(EZLOG_ERROR, "%d\t\t%s\n", k, buf);
        k++;
        struct host_resolve_uri *uri = host_resolve_get_parse_uri(buf);

        cb_url_check(&expect_uri, uri);

        host_uri_free(uri);
      }
    }
    mask_idx++;
  }
}

/* clang-format off */
 // [schema://[user[:password]@]]host[:port][/path][?query]
 struct test_dut test_array_good[] = {
   { .str = "schema://",  .expect = "schema",   .id = SCHEMA, .require = HOST },
   { .str = "user",       .expect = "user",     .id = USER, .require = HOST | OPTIONAL },
   { .str = ":password",  .expect = "password", .id = PASSWORD, .require = HOST | USER | OPTIONAL },
   { .str = "@",          .expect = "",         .id = OPTIONAL, .require = HOST | USER },
   { .str = "host.de",    .expect = "host.de",  .id = HOST, .require = 0 } ,
   { .str = ":1233",      .expect = "1233",     .id = PORT, .require = HOST},
   { .str =  "/my/path",  .expect = "my/path",  .id = PATH, .require = HOST },
   { .str = "?query=me",  .expect = "query=me", .id = QUERY, .require = HOST },
 };
/* clang-format on */

void
test_ok_cb(struct host_resolve_uri *expect, struct host_resolve_uri *found)
{
  if (!found)
    assert(0);

  ASSERT_CMP("schema", found->schema, expect->schema);
  ASSERT_CMP("user", found->user, expect->user);
  ASSERT_CMP("password", found->password, expect->password);
  ASSERT_CMP("host", found->host, expect->host);
  ASSERT_CMP("path", found->path, expect->path);
  ASSERT_CMP("query", found->query, expect->query);
  ezwebsocket_log(EZLOG_ERROR, "port: %d == %d\n", found->port, expect->port);

  if (found->port != expect->port)
    assert(0);
}

int
main(int args, char *argv[])
{
  test_uri(test_array_good, ARRAYSIZE(test_array_good), test_ok_cb);

  struct host_resolve_uri *uri = host_resolve_get_parse_uri(":/");
  assert(uri == NULL);

  uri = host_resolve_get_parse_uri("://");
  assert(uri == NULL);

  uri = host_resolve_get_parse_uri(NULL);
  assert(uri == NULL);

  uri = host_resolve_get_parse_uri("");
  assert(uri == NULL);

  uri = host_resolve_get_parse_uri("*:500");
  assert(uri == NULL);
  
  return 0;
}
