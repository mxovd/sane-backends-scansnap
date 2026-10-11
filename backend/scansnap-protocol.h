/* SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception */

#ifndef SCANSNAP_PROTOCOL_H
#define SCANSNAP_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define SS_MAX_IMAGE_BYTES (128U * 1024U * 1024U)

typedef enum
{
  SS_FEED_ADF = 0,
  SS_FEED_RETURN = 1
} SsFeed;

typedef struct
{
  char ip[64];
  char product[17];
  char serial[11];
  uint8_t magic[4];
  uint8_t identity[6];
  uint8_t local_ip[4];
  uint16_t scanner_port;
  uint16_t application_port;
} SsDevice;

typedef struct
{
  int top;
  int hopper_empty;
  int cover_open;
  int card_loaded;
  int error_code;
} SsHardwareStatus;

typedef struct
{
  uint8_t *data;
  size_t length;
} SsImage;

typedef struct
{
  SsDevice device;
  int scanner_fd;
  int trigger_fd;
  int reserved;
  unsigned int page_id;
} SsSession;

/* Discover a configured IPv4 target and verify that it is a plain-TCP iX1300. */
int ss_discover (const char *target, SsDevice *device, char *error, size_t error_size);

int ss_session_open (SsSession *session, const SsDevice *device,
                     char *error, size_t error_size);
int ss_hardware_status (SsSession *session, SsHardwareStatus *status,
                        char *error, size_t error_size);
int ss_scan_begin (SsSession *session, SsFeed feed, int duplex,
                   char *error, size_t error_size);
/* Returns 0 for a page, 1 for normal hopper-empty, and -1 on error. */
int ss_scan_next (SsSession *session, int duplex, SsImage *front,
                  SsImage *back, char *error, size_t error_size);
int ss_scan (SsSession *session, SsFeed feed, int duplex,
             SsImage *front, SsImage *back, char *error, size_t error_size);
void ss_image_free (SsImage *image);
void ss_session_close (SsSession *session);

#endif
