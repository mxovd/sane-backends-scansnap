/* SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception */
/* Offline replay through the production protocol's public entry points. */
#include <sane/config.h>
#include "scansnap-protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* Unlike assert(), checks must remain active in builds using -DNDEBUG. */
#define CHECK(expr) do { if (!(expr)) { \
  fprintf (stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
  exit (1); } } while (0)

/* Replace only stream I/O; run the actual production framing and scan code.
   Short reads/writes force read_all/write_all to handle fragmentation. */
static unsigned char incoming[8192], outgoing[8192];
static size_t incoming_size, incoming_offset, outgoing_size, outgoing_offset;

static ssize_t
replay_recv (int fd, void *buffer, size_t length, int flags)
{
  size_t available = incoming_size - incoming_offset;
  (void) fd; (void) flags;
  if (length > available) length = available;
  if (length > 3) length = 3;
  memcpy (buffer, incoming + incoming_offset, length);
  incoming_offset += length;
  return (ssize_t) length;
}

static ssize_t
replay_send (int fd, const void *buffer, size_t length, int flags)
{
  (void) fd; (void) flags;
  if (length > 7) length = 7;
  CHECK (length <= sizeof (outgoing) - outgoing_size);
  memcpy (outgoing + outgoing_size, buffer, length);
  outgoing_size += length;
  return (ssize_t) length;
}

#define recv replay_recv
#define send replay_send
#include "../../../backend/scansnap-protocol.c"
#undef recv
#undef send

static SsSession session;
static char error[256];

static void
put32 (unsigned char *p, unsigned int n)
{
  p[0] = n >> 24; p[1] = n >> 16; p[2] = n >> 8; p[3] = n;
}

static size_t
fixture (const char *name, unsigned char *data, size_t capacity)
{
  char path[1024];
  const char *directory = getenv ("SCANSNAP_FIXTURES");
  FILE *file;
  unsigned int value;
  size_t length = 0;
  snprintf (path, sizeof (path), "%s/%s.hex", directory ? directory : "fixtures", name);
  file = fopen (path, "r");
  CHECK (file != NULL);
  while (fscanf (file, "%x", &value) == 1)
    {
      CHECK (length < capacity && value <= 255);
      data[length++] = value;
    }
  CHECK (feof (file));
  CHECK (fclose (file) == 0);
  return length;
}

static void
start (void)
{
  incoming_size = incoming_offset = outgoing_size = outgoing_offset = 0;
  memset (&session, 0, sizeof (session));
  session.scanner_fd = -1;
  session.trigger_fd = -1;
  memcpy (session.device.magic, "VENS", 4);
  memcpy (session.device.identity, "\x00\x11\x22\x33\x44\x55", 6);
  error[0] = '\0';
}

static void
send_bytes (const unsigned char *data, size_t length)
{
  CHECK (length <= sizeof (incoming) - incoming_size);
  if (length) memcpy (incoming + incoming_size, data, length);
  incoming_size += length;
}

static void
reply (int status, int scanner_status, const unsigned char *payload, size_t length)
{
  unsigned char header[40] = {0};
  put32 (header, 40 + length);
  memcpy (header + 4, "VENS", 4);
  put32 (header + 8, status);
  put32 (header + 12, scanner_status);
  send_bytes (header, sizeof (header));
  send_bytes (payload, length);
}

static void
request (unsigned char *data, size_t length)
{
  CHECK (length <= outgoing_size - outgoing_offset);
  memcpy (data, outgoing + outgoing_offset, length);
  outgoing_offset += length;
}

static void
hardware_tests (void)
{
  const char *names[] = {"hardware_idle", "hardware_adf", "hardware_return"};
  size_t i;
  for (i = 0; i < 3; i++)
    {
      unsigned char data[32], sent[64], expected[64] = {0};
      SsHardwareStatus status;
      start ();
      CHECK (fixture (names[i], data, sizeof (data)) == 32);
      reply (0, 0, data, 32);
      CHECK (ss_hardware_status (&session, &status, error, sizeof (error)) == 0);
      CHECK (status.hopper_empty == (i != 1));
      CHECK (status.card_loaded == (i == 2) && status.top == (i == 2));
      CHECK (!status.cover_open && !status.error_code);
      request (sent, sizeof (sent));
      put32 (expected, 64);
      memcpy (expected + 4, "VENS", 4);
      expected[11] = 1;
      memcpy (expected + 16, "\x00\x11\x22\x33\x44\x55", 6);
      expected[35] = 10; expected[39] = 32;
      expected[48] = 0xc2; expected[56] = 32;
      CHECK (memcmp (sent, expected, 64) == 0);
    }
}

static void
malformed_tests (void)
{
  int kind;
  for (kind = 0; kind < 8; kind++)
    {
      unsigned char data[72] = {0};
      SsHardwareStatus status;
      start ();
      put32 (data, 72);
      memcpy (data + 4, "VENS", 4);
      switch (kind)
        {
        case 0: put32 (data, 39); break;
        case 1: put32 (data, 41U + SS_MAX_IMAGE_BYTES); break;
        case 2: data[4] = 'X'; break;
        case 3: put32 (data + 8, 1); break;
        case 4: put32 (data + 12, 2); break;
        case 5: put32 (data, 71); break;
        default: break;
        }
      send_bytes (data, kind == 6 ? 20 : kind == 7 ? 50 : sizeof (data));
      CHECK (ss_hardware_status (&session, &status, error, sizeof (error)) == -1);
      CHECK (error[0]);
    }
}

static void
begin_tests (void)
{
  int feed, duplex, state;
  for (state = 0; state < 3; state++)
    {
      unsigned char hardware[32] = {0};
      start ();
      hardware[3] = state == 0 ? 0x20 : state == 1 ? 0x80 : 0;
      reply (0, 0, hardware, 32);
      CHECK (ss_scan_begin (&session, state == 2 ? SS_FEED_RETURN : SS_FEED_ADF,
                            0, error, sizeof (error)) == (state == 0 ? -2 : -3));
      CHECK (error[0]);
    }
  for (feed = 0; feed < 2; feed++)
    for (duplex = 0; duplex < 2; duplex++)
      {
        unsigned char hardware[32] = {0}, job[8] = {0}, sent[344];
        const unsigned char *params;
        start ();
        hardware[3] = feed ? 1 : 0;
        reply (0, 0, hardware, 32);
        reply (0, 0, NULL, 0); /* D8 */
        reply (0, 0, NULL, 0); /* D4 */
        reply (0, 0, job, 8); /* D5 */
        session.page_id = 10;
        CHECK (ss_scan_begin (&session, (SsFeed) feed, duplex, error, sizeof (error)) == 0);
        CHECK (session.page_id == 0);
        request (sent, sizeof (sent));
        CHECK (sent[112] == 0xd8 && sent[176] == 0xd4 && sent[320] == 0xd5);
        params = sent + 192;
        CHECK (params[1] == (feed ? (duplex ? 6 : 4) : (duplex ? 3 : 1)));
        CHECK (params[6] == (feed ? 0x80 : 0xc1));
        CHECK (params[28] == (feed ? 0x20 : 0));
        CHECK (memcmp (params + 34, "\x01\x2c\x01\x2c", 4) == 0);
        CHECK (memcmp (params + 42, "\x00\x00\x28\x80", 4) == 0);
        CHECK (params[48] == (feed ? 0x44 : 0x43) && params[49] == (feed ? 0x10 : 0x50));
      }
}

static void
image_reply (int valid)
{
  unsigned char first[] = {0, 0, 0xff, 0xd8};
  unsigned char last[] = {0, 0, 0xff, 0xd9};
  unsigned char sense[18] = {0};
  if (!valid) last[3] = 0;
  reply (0, 0, first, sizeof (first));
  reply (0, 2, last, sizeof (last));
  sense[2] = 0x40; /* End of page. JPEG markers only, no document data. */
  reply (0, 0, sense, sizeof (sense));
}

static void
scan_tests (void)
{
  int mode;
  for (mode = 0; mode < 5; mode++)
    {
      SsImage front, back;
      unsigned char sent[448], sense[18] = {0};
      int result;
      start ();
      session.page_id = 4;
      reply (0, mode == 4 ? 2 : 0, NULL, 0);
      if (mode == 4)
        {
          sense[2] = 3; sense[12] = 0x80; sense[13] = 3;
          reply (0, 0, sense, sizeof (sense));
        }
      else
        {
          image_reply (mode != 2);
          if (mode == 1 || mode == 3) image_reply (mode != 3);
        }
      result = ss_scan_next (&session, mode == 1 || mode == 3, &front, &back, error, sizeof (error));
      CHECK (result == (mode == 4 ? 1 : mode >= 2 ? -1 : 0));
      if (result == 0)
        {
          CHECK (front.length == 4 && memcmp (front.data, "\xff\xd8\xff\xd9", 4) == 0);
          CHECK (back.length == (mode == 1 ? 4 : 0));
          if (mode == 1) CHECK (memcmp (back.data, front.data, 4) == 0);
          CHECK (session.page_id == (mode == 1 ? 6U : 5U));
          request (sent, mode == 1 ? 448 : 256);
          CHECK (sent[64 + 48] == 0x28 && sent[64 + 58] == 4 && sent[64 + 53] == 0);
          CHECK (sent[128 + 59] == 1);
          if (mode == 1) CHECK (sent[256 + 58] == 5 && sent[256 + 53] == 0x80);
        }
      else
        {
          CHECK (!front.data && !front.length && !back.data && !back.length);
          CHECK (session.page_id == 4);
        }
      ss_image_free (&front);
      ss_image_free (&back);
      ss_image_free (&front); /* Cleanup is idempotent. */
    }
}

int
main (void)
{
  hardware_tests ();
  malformed_tests ();
  begin_tests ();
  scan_tests ();
  puts ("ScanSnap: 23 offline C replay cases passed");
  return 0;
}
