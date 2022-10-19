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
#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <ezwebsocket_log.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
static int init_syslog = 1;
#endif

static int
vlog_continue(enum ezwebsocket_log_level log_level, const char *fmt, va_list argp);
static int
vlog(enum ezwebsocket_log_level log_level, const char *name, const char *fm, va_list ap);

static ezwebsocket_log_func_t log_handler = vlog;
static ezwebsocket_log_cont_func_t log_continue_handler = vlog_continue;
static int _log_level = EZLOG_ERROR;

static int
ezwebsocket_log_level_is_enabled(enum ezwebsocket_log_level level)
{
  return _log_level >= level;
}

static char *
ezwebsocket_log_timestamp(char *buf, size_t len)
{
  struct timeval tv;
  struct tm *_time;
  char timestr[128];

  gettimeofday(&tv, NULL);

  _time = localtime(&tv.tv_sec);
  if (_time == NULL) {
    snprintf(buf, len, "%s", "[unknown] ");
    return buf;
  }

  strftime(timestr, sizeof(timestr), "%H:%M:%S", _time);
  snprintf(buf, len, "[%s.%03li]", timestr, (tv.tv_usec / 1000));
  return buf;
}

#ifdef HAVE_SYSLOG_H
static int
ezwebsocket_log_level_to_syslog_prio(enum ezwebsocket_log_level log_level)
{
  switch (log_level) {
  case EZLOG_ERROR:
    return LOG_ERR;
    break;
  case EZLOG_WARNING:
    return LOG_WARNING;
    break;
  case EZLOG_INFO:
    return LOG_INFO;
    break;
  default:
    return LOG_DEBUG;
  }
  return LOG_DEBUG;
}
#endif

static int
ezwebsocket_log_level_vprintf(enum ezwebsocket_log_level log_level, char *fmt, va_list ap)
{
  int len;
#ifdef HAVE_SYSLOG_H
  if (init_syslog) {
    openlog("ezwebsocket", LOG_CONS | LOG_PID, LOG_USER);
    init_syslog = 0;
  }
  vsyslog(ezwebsocket_log_level_to_syslog_prio(log_level), fmt, ap);
  len = 0;
#else
  switch (log_level) {
  case EZLOG_ERROR:
    len = vfprintf(stderr, fmt, ap);
    break;
  default:
    len = vfprintf(stdout, fmt, ap);
    break;
  }
#endif
  return len;
}

static int
ezwebsocket_log_level_printf(enum ezwebsocket_log_level log_level, char *fmt, ...)
{
  va_list ap;
  int len;

  va_start(ap, fmt);
  len = ezwebsocket_log_level_vprintf(log_level, fmt, ap);
  va_end(ap);

  return len;
}

static int
vlog(enum ezwebsocket_log_level log_level, const char *name, const char *fmt, va_list ap)
{
  const char *err = "error log";
  char timestr[128];
  int len = 0;
  char *str;

  if (ezwebsocket_log_level_is_enabled(log_level)) {
    int len_va;
    char *log_timestamp = ezwebsocket_log_timestamp(timestr, sizeof(timestr));

    len_va = vasprintf(&str, fmt, ap);
    if (len_va >= 0) {
      len = ezwebsocket_log_level_printf(log_level, "%s (%s) %s", log_timestamp, name ? name : "",
                                         str);
      free(str);
    } else {
      len = ezwebsocket_log_level_printf(log_level, "%s (%s) %s", log_timestamp, name ? name : "",
                                         err);
    }
  }

  return len;
}

static int
vlog_continue(enum ezwebsocket_log_level log_level, const char *fmt, va_list argp)
{

  if (ezwebsocket_log_level_is_enabled(log_level))
    return ezwebsocket_log_level_vprintf(log_level, (char *) fmt, argp);
  return 0;
}

void
ezwebsocket_log_set_handler(ezwebsocket_log_func_t log, ezwebsocket_log_cont_func_t cont)
{
  log_handler = log;
  log_continue_handler = cont;
}

void
ezwebsocket_set_level(enum ezwebsocket_log_level level)
{
  _log_level = level;
}

int
ezwebsocket_vlog_named(enum ezwebsocket_log_level log_level, const char *name, const char *fmt,
                       va_list ap)
{
  if (!log_handler)
    return 0;

  return log_handler(log_level, name, fmt, ap);
}

int
ezwebsocket_vlog_continue(enum ezwebsocket_log_level log_level, const char *fmt, va_list argp)
{
  if (!log_continue_handler)
    return 0;

  return log_continue_handler(log_level, fmt, argp);
}

int
ezwebsocket_log_named(enum ezwebsocket_log_level log_level, const char *name, const char *fmt, ...)
{
  int l;
  va_list argp;

  va_start(argp, fmt);
  l = ezwebsocket_vlog_named(log_level, name, fmt, argp);
  va_end(argp);

  return l;
}

int
ezwebsocket_log_continue(enum ezwebsocket_log_level log_level, const char *fmt, ...)
{
  int l;
  va_list argp;

  va_start(argp, fmt);
  l = ezwebsocket_vlog_continue(log_level, fmt, argp);
  va_end(argp);

  return l;
}
