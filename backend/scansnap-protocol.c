/* SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception */
/* Network protocol used by ScanSnap Home for the iX1300. */

#include "../include/sane/config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __linux__
#include <netpacket/packet.h>
#endif
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "scansnap-protocol.h"

#define SS_DISCOVERY_PORT 52217
#define SS_REPLY_PORT 55274
#define SS_TRIGGER_PORT 55275
#define SS_READ_BLOCK 256000U
#define SS_MAX_BLOCKS 512

#ifdef MSG_NOSIGNAL
#define SS_SEND_FLAGS MSG_NOSIGNAL
#else
#define SS_SEND_FLAGS 0
#endif

static void
set_error (char *error, size_t size, const char *format, ...)
{
  va_list args;
  if (!error || !size)
    return;
  va_start (args, format);
  vsnprintf (error, size, format, args);
  va_end (args);
}

static uint16_t
get_be16 (const uint8_t *p)
{
  return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static uint32_t
get_be32 (const uint8_t *p)
{
  return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
       | ((uint32_t) p[2] << 8) | p[3];
}

static void
put_be16 (uint8_t *p, uint16_t value)
{
  p[0] = (uint8_t) (value >> 8);
  p[1] = (uint8_t) value;
}

static void
put_be32 (uint8_t *p, uint32_t value)
{
  p[0] = (uint8_t) (value >> 24);
  p[1] = (uint8_t) (value >> 16);
  p[2] = (uint8_t) (value >> 8);
  p[3] = (uint8_t) value;
}

static int
write_all (int fd, const void *buffer, size_t length)
{
  const uint8_t *p = buffer;
  while (length)
    {
      ssize_t written = send (fd, p, length, SS_SEND_FLAGS);
      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        return -1;
      p += written;
      length -= (size_t) written;
    }
  return 0;
}

static int
read_all (int fd, void *buffer, size_t length)
{
  uint8_t *p = buffer;
  while (length)
    {
      ssize_t count = recv (fd, p, length, 0);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        return -1;
      p += count;
      length -= (size_t) count;
    }
  return 0;
}

static int
route_identity (const struct sockaddr_in *target, uint8_t local_ip[4],
                uint8_t identity[6], char *error, size_t error_size)
{
  struct sockaddr_in local;
  socklen_t local_len = sizeof (local);
  struct ifaddrs *addresses = NULL, *entry;
  char interface[IF_NAMESIZE] = "";
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0 || connect (fd, (const struct sockaddr *) target, sizeof (*target)) < 0
      || getsockname (fd, (struct sockaddr *) &local, &local_len) < 0)
    {
      set_error (error, error_size, "cannot determine route to scanner: %s",
                 strerror (errno));
      if (fd >= 0) close (fd);
      return -1;
    }
  close (fd);
  memcpy (local_ip, &local.sin_addr, 4);

  if (getifaddrs (&addresses) < 0)
    {
      set_error (error, error_size, "cannot list network interfaces: %s",
                 strerror (errno));
      return -1;
    }
  for (entry = addresses; entry; entry = entry->ifa_next)
    if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET
        && !memcmp (&((struct sockaddr_in *) entry->ifa_addr)->sin_addr,
                    &local.sin_addr, 4))
      {
        snprintf (interface, sizeof (interface), "%s", entry->ifa_name);
        break;
      }
#ifdef __linux__
  for (entry = addresses; interface[0] && entry; entry = entry->ifa_next)
    if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_PACKET
        && !strcmp (entry->ifa_name, interface))
      {
        const struct sockaddr_ll *link = (const struct sockaddr_ll *) entry->ifa_addr;
        if (link->sll_halen == 6)
          {
            memcpy (identity, link->sll_addr, 6);
            freeifaddrs (addresses);
            return 0;
          }
      }
#endif
  freeifaddrs (addresses);
  set_error (error, error_size, "cannot determine the route interface MAC address");
  return -1;
}

static void
socket_timeout (int fd, int seconds)
{
  struct timeval timeout;
  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout));
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof (timeout));
}

int
ss_discover (const char *target_text, SsDevice *device, char *error,
             size_t error_size)
{
  struct sockaddr_in target, local, peer;
  uint8_t request[32] = {0}, reply[512];
  socklen_t peer_len = sizeof (peer);
  ssize_t count;
  uint32_t scanner_port, application_port;
  int fd, attempt, one = 1;

  memset (device, 0, sizeof (*device));
  memset (&target, 0, sizeof (target));
  target.sin_family = AF_INET;
  target.sin_port = htons (SS_DISCOVERY_PORT);
  if (inet_pton (AF_INET, target_text, &target.sin_addr) != 1)
    {
      set_error (error, error_size, "invalid scanner IPv4 address: %s", target_text);
      return -1;
    }
  if (route_identity (&target, device->local_ip, device->identity,
                      error, error_size) < 0)
    return -1;

  memcpy (request, "VENS", 4);
  memcpy (request + 8, device->local_ip, 4);
  memcpy (request + 12, device->identity, 6);
  put_be32 (request + 20, SS_REPLY_PORT);
  put_be16 (request + 24, 16);

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    goto socket_error;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
  socket_timeout (fd, 2);
  memset (&local, 0, sizeof (local));
  local.sin_family = AF_INET;
  local.sin_port = htons (SS_REPLY_PORT);
  memcpy (&local.sin_addr, device->local_ip, 4);
  if (bind (fd, (struct sockaddr *) &local, sizeof (local)) < 0)
    goto socket_error_close;
  for (attempt = 0; attempt < 3; attempt++)
    sendto (fd, request, sizeof (request), 0,
            (struct sockaddr *) &target, sizeof (target));
  do
    {
      count = recvfrom (fd, reply, sizeof (reply), 0,
                        (struct sockaddr *) &peer, &peer_len);
    }
  while (count >= 0 && peer.sin_addr.s_addr != target.sin_addr.s_addr);
  close (fd);
  if (count < 144)
    {
      set_error (error, error_size, "no valid discovery reply from %s", target_text);
      return -1;
    }
  if (memcmp (reply, "VENS", 4) || get_be16 (reply + 4) > 1
      || get_be16 (reply + 6) != 0 || get_be16 (reply + 8) != 16
      || get_be16 (reply + 10) != 48 || get_be32 (reply + 12) != 0
      || memcmp (reply + 16, &target.sin_addr, 4))
    {
      set_error (error, error_size, "unsupported discovery reply from %s", target_text);
      return -1;
    }
  memcpy (device->magic, reply, 4);
  scanner_port = get_be32 (reply + 20);
  application_port = get_be32 (reply + 24);
  if (scanner_port > 65535 || application_port > 65535)
    {
      set_error (error, error_size, "scanner advertised an invalid TCP port");
      return -1;
    }
  device->scanner_port = (uint16_t) scanner_port;
  device->application_port = (uint16_t) application_port;
  memcpy (device->product, reply + 104, 16);
  device->product[16] = '\0';
  memcpy (device->serial, reply + 132, 10);
  device->serial[10] = '\0';
  {
    size_t length = strlen (device->product);
    while (length && device->product[length - 1] == ' ')
      device->product[--length] = '\0';
    length = strlen (device->serial);
    while (length && device->serial[length - 1] == ' ')
      device->serial[--length] = '\0';
  }
  snprintf (device->ip, sizeof (device->ip), "%s", target_text);
  if (strcmp (device->product, "ScanSnap iX1300") != 0
      || (reply[36] & 8) || device->scanner_port == 0
      || device->application_port == 0)
    {
      set_error (error, error_size, "target is not a supported plain-TCP iX1300");
      return -1;
    }
  return 0;

socket_error_close:
  close (fd);
socket_error:
  set_error (error, error_size, "discovery socket failed: %s", strerror (errno));
  return -1;
}

static int
connect_greet (const SsDevice *device, uint16_t port, char *error, size_t error_size)
{
  struct sockaddr_in remote, local;
  uint8_t greeting[16];
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    goto failed;
  socket_timeout (fd, 15);
  memset (&local, 0, sizeof (local));
  local.sin_family = AF_INET;
  memcpy (&local.sin_addr, device->local_ip, 4);
  if (bind (fd, (struct sockaddr *) &local, sizeof (local)) < 0)
    goto failed_close;
  memset (&remote, 0, sizeof (remote));
  remote.sin_family = AF_INET;
  remote.sin_port = htons (port);
  if (inet_pton (AF_INET, device->ip, &remote.sin_addr) != 1
      || connect (fd, (struct sockaddr *) &remote, sizeof (remote)) < 0
      || read_all (fd, greeting, sizeof (greeting)) < 0)
    goto failed_close;
  if (get_be32 (greeting) != 16 || memcmp (greeting + 4, device->magic, 4)
      || get_be32 (greeting + 8) != 0)
    {
      set_error (error, error_size, "invalid greeting from scanner");
      close (fd);
      return -1;
    }
  return fd;

failed_close:
  close (fd);
failed:
  set_error (error, error_size, "connection to scanner failed: %s", strerror (errno));
  return -1;
}

static void
common_header (uint8_t *packet, size_t length, const SsDevice *device,
               uint32_t operation)
{
  memset (packet, 0, length);
  put_be32 (packet, (uint32_t) length);
  memcpy (packet + 4, device->magic, 4);
  put_be32 (packet + 8, operation);
  memcpy (packet + 16, device->identity, 6);
}

static int
application_command (const SsDevice *device, const uint8_t *request,
                     size_t request_size, size_t reply_size,
                     char *error, size_t error_size)
{
  uint8_t reply[32];
  int fd = connect_greet (device, device->application_port, error, error_size);
  if (fd < 0)
    return -1;
  if (reply_size > sizeof (reply) || write_all (fd, request, request_size) < 0
      || read_all (fd, reply, reply_size) < 0)
    {
      set_error (error, error_size, "application command failed: %s", strerror (errno));
      close (fd);
      return -1;
    }
  close (fd);
  if (get_be32 (reply) != reply_size || memcmp (reply + 4, device->magic, 4)
      || get_be32 (reply + 8) != 0)
    {
      set_error (error, error_size, "application command was rejected");
      return -1;
    }
  return 0;
}

int
ss_session_open (SsSession *session, const SsDevice *device,
                 char *error, size_t error_size)
{
  uint8_t request[128];
  struct sockaddr_in trigger;
  time_t now;
  struct tm local_tm, utc_tm;
  long utc_offset;

  memset (session, 0, sizeof (*session));
  session->scanner_fd = session->trigger_fd = -1;
  session->device = *device;
  session->trigger_fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (session->trigger_fd < 0)
    goto failed;
  memset (&trigger, 0, sizeof (trigger));
  trigger.sin_family = AF_INET;
  trigger.sin_port = htons (SS_TRIGGER_PORT);
  memcpy (&trigger.sin_addr, device->local_ip, 4);
  if (bind (session->trigger_fd, (struct sockaddr *) &trigger, sizeof (trigger)) < 0)
    goto failed;

  common_header (request, sizeof (request), device, 17);
  put_be16 (request + 32, 16);
  request[34] = 30;
  put_be32 (request + 36, 1);
  memcpy (request + 44, device->local_ip, 4);
  put_be32 (request + 48, SS_TRIGGER_PORT);
  now = time (NULL);
  localtime_r (&now, &local_tm);
  gmtime_r (&now, &utc_tm);
  put_be32 (request + 100, ((uint32_t) (local_tm.tm_year + 1900) << 16)
            | ((uint32_t) (local_tm.tm_mon + 1) << 8) | local_tm.tm_mday);
  put_be32 (request + 104, ((uint32_t) local_tm.tm_hour << 24)
            | ((uint32_t) local_tm.tm_min << 16) | ((uint32_t) local_tm.tm_sec << 8));
  utc_offset = (long) difftime (mktime (&utc_tm), mktime (&local_tm));
  put_be32 (request + 116, (uint32_t) utc_offset);
  if (application_command (device, request, sizeof (request), 20,
                           error, error_size) < 0)
    goto failed;
  session->reserved = 1;
  session->scanner_fd = connect_greet (device, device->scanner_port,
                                       error, error_size);
  if (session->scanner_fd < 0)
    goto failed;
  return 0;

failed:
  ss_session_close (session);
  return -1;
}

typedef struct
{
  int status;
  int scanner_status;
  uint8_t *payload;
  size_t length;
} SsReply;

static void
reply_free (SsReply *reply)
{
  free (reply->payload);
  memset (reply, 0, sizeof (*reply));
}

static int
exchange (SsSession *session, const uint8_t *cdb, size_t cdb_size,
          size_t incoming, const uint8_t *outgoing, size_t outgoing_size,
          SsReply *reply, char *error, size_t error_size)
{
  uint8_t header[64], response[40];
  uint32_t total;
  if (cdb_size < 1 || cdb_size > 16 || incoming > SS_MAX_IMAGE_BYTES
      || outgoing_size > 65536)
    return -1;
  common_header (header, sizeof (header), &session->device, 1);
  put_be32 (header, (uint32_t) (sizeof (header) + outgoing_size));
  put_be32 (header + 32, (uint32_t) cdb_size);
  put_be32 (header + 36, (uint32_t) incoming);
  put_be32 (header + 40, (uint32_t) outgoing_size);
  memcpy (header + 48, cdb, cdb_size);
  if (write_all (session->scanner_fd, header, sizeof (header)) < 0
      || (outgoing_size && write_all (session->scanner_fd, outgoing, outgoing_size) < 0)
      || read_all (session->scanner_fd, response, sizeof (response)) < 0)
    goto io_error;
  total = get_be32 (response);
  if (total < 40 || total > 40 + SS_MAX_IMAGE_BYTES
      || memcmp (response + 4, session->device.magic, 4))
    {
      set_error (error, error_size, "invalid scanner command reply");
      return -1;
    }
  memset (reply, 0, sizeof (*reply));
  reply->status = (int32_t) get_be32 (response + 8);
  reply->scanner_status = (int32_t) get_be32 (response + 12);
  reply->length = total - 40;
  if (reply->length)
    {
      reply->payload = malloc (reply->length);
      if (!reply->payload)
        {
          set_error (error, error_size, "out of memory receiving scanner data");
          return -1;
        }
      if (read_all (session->scanner_fd, reply->payload, reply->length) < 0)
        {
          reply_free (reply);
          goto io_error;
        }
    }
  return 0;

io_error:
  set_error (error, error_size, "scanner command I/O failed: %s", strerror (errno));
  return -1;
}

static int
simple_command (SsSession *session, uint8_t opcode)
{
  uint8_t cdb[6] = {0};
  SsReply reply;
  int result;
  cdb[0] = opcode;
  result = exchange (session, cdb, sizeof (cdb), 0, NULL, 0,
                     &reply, NULL, 0);
  if (result == 0)
    {
      result = reply.status || reply.scanner_status || reply.length ? -1 : 0;
      reply_free (&reply);
    }
  return result;
}

int
ss_hardware_status (SsSession *session, SsHardwareStatus *status,
                    char *error, size_t error_size)
{
  uint8_t cdb[10] = {0};
  SsReply reply;
  cdb[0] = 0xc2;
  cdb[8] = 32;
  if (exchange (session, cdb, sizeof (cdb), 32, NULL, 0,
                &reply, error, error_size) < 0)
    return -1;
  if (reply.status || reply.scanner_status || reply.length != 32)
    {
      reply_free (&reply);
      set_error (error, error_size, "GET HARDWARE STATUS failed");
      return -1;
    }
  memset (status, 0, sizeof (*status));
  status->top = !!(reply.payload[2] & 0x80);
  status->hopper_empty = !!(reply.payload[3] & 0x80);
  status->cover_open = !!(reply.payload[3] & 0x20);
  status->card_loaded = !!(reply.payload[3] & 0x01);
  status->error_code = reply.payload[7];
  reply_free (&reply);
  return 0;
}

static void
scan_parameters (uint8_t data[80], SsFeed feed, int duplex)
{
  size_t offset = 32;
  memset (data, 0, 80);
  data[0] = 1;
  data[1] = feed == SS_FEED_ADF ? (duplex ? 3 : 1) : (duplex ? 6 : 4);
  data[2] = data[3] = data[5] = 1;
  data[4] = 0x80;
  data[6] = feed == SS_FEED_ADF ? 0xc1 : 0x80;
  data[7] = data[8] = data[10] = data[11] = 0x80;
  data[9] = 0xc8;
  if (feed == SS_FEED_RETURN)
    data[28] = 0x20;
  data[31] = 48;
  data[offset + 1] = 16;
  put_be16 (data + offset + 2, 300);
  put_be16 (data + offset + 4, 300);
  data[offset + 6] = 5;
  data[offset + 7] = 0x82;
  data[offset + 8] = 11;
  put_be32 (data + offset + 10, 10368);
  put_be32 (data + offset + 14, feed == SS_FEED_ADF ? 17232 : 17424);
  data[offset + 18] = 4;
  data[offset + 22] = data[offset + 23] = data[offset + 24] = 1;
}

static int
request_sense (SsSession *session, uint8_t sense[18], char *error, size_t error_size)
{
  uint8_t cdb[6] = {0x03, 0, 0, 0, 0x12, 0};
  SsReply reply;
  if (exchange (session, cdb, sizeof (cdb), 18, NULL, 0,
                &reply, error, error_size) < 0)
    return -1;
  if (reply.status || reply.scanner_status || reply.length != 18)
    {
      reply_free (&reply);
      set_error (error, error_size, "REQUEST SENSE failed");
      return -1;
    }
  memcpy (sense, reply.payload, 18);
  reply_free (&reply);
  return 0;
}

static int
image_append (SsImage *image, const uint8_t *data, size_t length,
              char *error, size_t error_size)
{
  uint8_t *expanded;
  if (length < 2 || image->length > SS_MAX_IMAGE_BYTES - (length - 2))
    {
      set_error (error, error_size, "invalid or oversized image block");
      return -1;
    }
  expanded = realloc (image->data, image->length + length - 2);
  if (!expanded)
    {
      set_error (error, error_size, "out of memory buffering image");
      return -1;
    }
  image->data = expanded;
  memcpy (image->data + image->length, data + 2, length - 2);
  image->length += length - 2;
  return 0;
}

static int
read_image (SsSession *session, int page, int front, SsImage *image,
            char *error, size_t error_size)
{
  int sequence;
  memset (image, 0, sizeof (*image));
  for (sequence = 0; sequence < SS_MAX_BLOCKS; sequence++)
    {
      uint8_t cdb[12] = {0}, sense[18];
      SsReply reply;
      cdb[0] = 0x28;
      cdb[3] = 2;
      cdb[5] = front ? 0 : 0x80;
      cdb[6] = (uint8_t) (SS_READ_BLOCK >> 16);
      cdb[7] = (uint8_t) (SS_READ_BLOCK >> 8);
      cdb[8] = (uint8_t) SS_READ_BLOCK;
      cdb[10] = (uint8_t) page;
      cdb[11] = (uint8_t) sequence;
      if (exchange (session, cdb, sizeof (cdb), SS_READ_BLOCK, NULL, 0,
                    &reply, error, error_size) < 0)
        goto failed;
      if (reply.status || (reply.scanner_status != 0 && reply.scanner_status != 2)
          || (reply.length && image_append (image, reply.payload, reply.length,
                                            error, error_size) < 0))
        {
          reply_free (&reply);
          goto failed;
        }
      if (reply.scanner_status == 0)
        {
          reply_free (&reply);
          continue;
        }
      reply_free (&reply);
      if (request_sense (session, sense, error, error_size) < 0)
        goto failed;
      if (sense[2] & 0x40)
        break;
      if ((sense[2] & 0x0f) == 3 && sense[12] == 0x80 && sense[13] == 0x13)
        continue;
      set_error (error, error_size, "image READ check condition %02x/%02x/%02x",
                 sense[2] & 0x0f, sense[12], sense[13]);
      goto failed;
    }
  if (sequence == SS_MAX_BLOCKS || image->length < 4
      || image->data[0] != 0xff || image->data[1] != 0xd8
      || image->data[image->length - 2] != 0xff
      || image->data[image->length - 1] != 0xd9)
    {
      set_error (error, error_size, "scanner returned an incomplete JPEG image");
      goto failed;
    }
  return 0;

failed:
  ss_image_free (image);
  return -1;
}

int
ss_scan_begin (SsSession *session, SsFeed feed, int duplex,
               char *error, size_t error_size)
{
  uint8_t parameters[80], cdb[6] = {0};
  SsHardwareStatus hardware;
  SsReply reply;
  if (ss_hardware_status (session, &hardware, error, error_size) < 0)
    return -1;
  if (hardware.cover_open)
    {
      set_error (error, error_size, "scanner cover is open");
      return -2;
    }
  if ((feed == SS_FEED_ADF && hardware.hopper_empty)
      || (feed == SS_FEED_RETURN && !hardware.card_loaded))
    {
      set_error (error, error_size, "no document loaded in the selected path");
      return -3;
    }
  simple_command (session, 0xd8);
  scan_parameters (parameters, feed, duplex);
  cdb[0] = 0xd4;
  cdb[4] = sizeof (parameters);
  if (exchange (session, cdb, sizeof (cdb), 0, parameters, sizeof (parameters),
                &reply, error, error_size) < 0)
    return -1;
  if (reply.status || reply.scanner_status || reply.length)
    {
      reply_free (&reply);
      set_error (error, error_size, "SET PARAMS failed");
      return -1;
    }
  reply_free (&reply);
  memset (cdb, 0, sizeof (cdb));
  cdb[0] = 0xd5;
  cdb[4] = cdb[5] = 8;
  {
    uint8_t job[8] = {0};
    if (exchange (session, cdb, sizeof (cdb), 8, job, sizeof (job),
                  &reply, error, error_size) < 0)
      return -1;
  }
  if (reply.status || reply.scanner_status || reply.length != 8)
    {
      reply_free (&reply);
      set_error (error, error_size, "START JOB failed");
      return -1;
    }
  reply_free (&reply);
  session->page_id = 0;
  return 0;
}

int
ss_scan_next (SsSession *session, int duplex, SsImage *front, SsImage *back,
              char *error, size_t error_size)
{
  uint8_t cdb[6] = {0}, sense[18];
  SsReply reply;
  int attempt;
  memset (front, 0, sizeof (*front));
  memset (back, 0, sizeof (*back));
  for (attempt = 0; attempt < 40; attempt++)
    {
      memset (cdb, 0, sizeof (cdb));
      cdb[0] = 0xe0;
      if (exchange (session, cdb, sizeof (cdb), 0, NULL, 0,
                    &reply, error, error_size) < 0)
        return -1;
      if (!reply.status && !reply.scanner_status)
        {
          reply_free (&reply);
          break;
        }
      if (!reply.status && reply.scanner_status == 2)
        {
          reply_free (&reply);
          if (request_sense (session, sense, error, error_size) < 0)
            return -1;
          if ((sense[2] & 0x0f) == 3 && sense[12] == 0x80
              && sense[13] == 3)
            return 1; /* Android's client treats ASC/ASCQ 80/03 as hopper empty. */
          set_error (error, error_size, "START PAPER check condition %02x/%02x/%02x",
                     sense[2] & 0x0f, sense[12], sense[13]);
          return -1;
        }
      if (reply.status || reply.scanner_status != 8)
        {
          reply_free (&reply);
          set_error (error, error_size, "START PAPER failed");
          return -1;
        }
      reply_free (&reply);
      usleep (100000);
    }
  if (attempt == 40)
    {
      set_error (error, error_size, "scanner remained busy starting paper");
      return -1;
    }
  if (read_image (session, (int) session->page_id, 1, front,
                  error, error_size) < 0
      || (duplex && read_image (session, (int) session->page_id + 1, 0,
                                back, error, error_size) < 0))
    {
      ss_image_free (front);
      ss_image_free (back);
      return -1;
    }
  session->page_id += duplex ? 2U : 1U;
  return 0;
}

int
ss_scan (SsSession *session, SsFeed feed, int duplex, SsImage *front,
         SsImage *back, char *error, size_t error_size)
{
  int result = ss_scan_begin (session, feed, duplex, error, error_size);
  if (result < 0)
    return result;
  result = ss_scan_next (session, duplex, front, back, error, error_size);
  return result == 1 ? -3 : result;
}

void
ss_image_free (SsImage *image)
{
  if (!image) return;
  free (image->data);
  image->data = NULL;
  image->length = 0;
}

void
ss_session_close (SsSession *session)
{
  uint8_t request[32];
  if (!session) return;
  if (session->scanner_fd >= 0)
    {
      simple_command (session, 0xd8);
      simple_command (session, 0xd6);
      close (session->scanner_fd);
      session->scanner_fd = -1;
    }
  if (session->reserved)
    {
      common_header (request, sizeof (request), &session->device, 18);
      put_be32 (request + 24, 1);
      application_command (&session->device, request, sizeof (request), 16, NULL, 0);
      session->reserved = 0;
    }
  if (session->trigger_fd >= 0)
    {
      close (session->trigger_fd);
      session->trigger_fd = -1;
    }
}
