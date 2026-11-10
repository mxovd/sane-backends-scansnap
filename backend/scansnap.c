/* SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception */
/* sane - Scanner Access Now Easy.
   Network backend for the ScanSnap iX1300. */

#define BUILD 1

#include "../include/sane/config.h"

#include <ctype.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jpeglib.h>
#include <jerror.h>

#include "../include/sane/sane.h"
#include "../include/sane/sanei.h"
#include "../include/sane/saneopts.h"
#include "../include/sane/sanei_backend.h"
#include "../include/sane/sanei_config.h"

#define BACKEND_NAME scansnap
#include "../include/sane/sanei_debug.h"

#include "scansnap-protocol.h"

#define SCANSNAP_CONFIG_FILE "scansnap.conf"
#define MAX_ERROR 256

enum
{
  OPT_NUM_OPTS = 0,
  OPT_STANDARD_GROUP,
  OPT_SOURCE,
  OPT_MODE,
  OPT_RESOLUTION,
  OPT_ENHANCEMENT_GROUP,
  OPT_AUTO_SIZE,
  OPT_ROTATE,
  OPT_DEVICE_GROUP,
  OPT_FEED_PATH,
  OPT_SERIAL,
  NUM_OPTIONS
};

typedef struct Device Device;
struct Device
{
  Device *next;
  SANE_Device sane;
  SsDevice protocol;
  SsFeed feed;
  SANE_Bool rotate;
  int open;
};

typedef struct
{
  Device *device;
  SANE_Option_Descriptor options[NUM_OPTIONS];
  char source[32];
  char mode[16];
  SANE_Word resolution;
  SANE_Bool auto_size;
  SANE_Bool rotate;
  uint8_t *front;
  size_t front_size;
  uint8_t *back;
  size_t back_size;
  int back_width;
  int back_height;
  uint8_t *current;
  size_t current_size;
  size_t offset;
  int width;
  int height;
  int scanning;
  int duplex;
  SsSession session;
  int job_active;
  SANE_Parameters params;
} Handle;

typedef struct
{
  struct jpeg_error_mgr standard;
  jmp_buf jump;
  char message[JMSG_LENGTH_MAX];
} JpegError;

static Device *devices;
static const SANE_Device **device_list;
static size_t device_count;
static SANE_Bool initialized;

/* scansnap.conf settings, indexed by SsFeed.  They apply to every scanner in
   the file, wherever the setting appears relative to its "net" lines. */
#define MAX_TARGETS 16
static SANE_Bool config_rotate[2];
static SANE_Bool config_return_path = SANE_TRUE;

static const SANE_String_Const source_list[] = {
  "ADF Front", "ADF Duplex", NULL
};
static const SANE_String_Const mode_list[] = {
  SANE_VALUE_SCAN_MODE_COLOR, SANE_VALUE_SCAN_MODE_GRAY,
  SANE_VALUE_SCAN_MODE_LINEART, NULL
};
static const SANE_Word resolution_list[] = { 1, 300 };

static char *
copy_string (const char *value)
{
  size_t length = strlen (value) + 1;
  char *copy = malloc (length);
  if (copy) memcpy (copy, value, length);
  return copy;
}

static void
jpeg_error_exit (j_common_ptr info)
{
  JpegError *error = (JpegError *) info->err;
  (*info->err->format_message) (info, error->message);
  longjmp (error->jump, 1);
}

/* Rotate a packed 8-bit image by 180 degrees in place.  Rows have no padding,
   so reversing the order of all pixels reverses both rows and columns. */
static void
rotate_180 (uint8_t *pixels, size_t count, size_t pixel_bytes)
{
  size_t first = 0, last = count;
  uint8_t swap[3];
  while (last > first + 1)
    {
      uint8_t *a = pixels + first * pixel_bytes;
      uint8_t *b = pixels + --last * pixel_bytes;
      memcpy (swap, a, pixel_bytes);
      memcpy (a, b, pixel_bytes);
      memcpy (b, swap, pixel_bytes);
      first++;
    }
}

static SANE_Status
decode_jpeg (const SsImage *jpeg, const char *mode, SANE_Bool rotate,
             uint8_t **pixels, size_t *size, int *width, int *height,
             char *message, size_t message_size)
{
  struct jpeg_decompress_struct info;
  JpegError error;
  uint8_t * volatile output = NULL;
  int color = !strcmp (mode, SANE_VALUE_SCAN_MODE_COLOR);
  int lineart = !strcmp (mode, SANE_VALUE_SCAN_MODE_LINEART);
  size_t row_bytes, output_size;

  memset (&info, 0, sizeof (info));
  info.err = jpeg_std_error (&error.standard);
  error.standard.error_exit = jpeg_error_exit;
  if (setjmp (error.jump))
    {
      jpeg_destroy_decompress (&info);
      free (output);
      snprintf (message, message_size, "invalid JPEG from scanner: %s", error.message);
      return SANE_STATUS_IO_ERROR;
    }
  jpeg_create_decompress (&info);
  jpeg_mem_src (&info, jpeg->data, jpeg->length);
  jpeg_read_header (&info, TRUE);
  info.out_color_space = color ? JCS_RGB : JCS_GRAYSCALE;
  jpeg_start_decompress (&info);
  if (!info.output_width || !info.output_height || info.output_components != (color ? 3 : 1)
      || info.output_width > 20000 || info.output_height > 100000)
    ERREXIT (&info, JERR_BAD_STATE);
  row_bytes = (size_t) info.output_width * (color ? 3 : 1);
  if (info.output_height > SIZE_MAX / row_bytes)
    ERREXIT (&info, JERR_OUT_OF_MEMORY);
  output_size = row_bytes * info.output_height;
  if (output_size > 512U * 1024U * 1024U)
    ERREXIT (&info, JERR_OUT_OF_MEMORY);
  output = malloc (output_size);
  if (!output)
    ERREXIT (&info, JERR_OUT_OF_MEMORY);
  while (info.output_scanline < info.output_height)
    {
      JSAMPROW row = output + (size_t) info.output_scanline * row_bytes;
      jpeg_read_scanlines (&info, &row, 1);
    }
  *width = (int) info.output_width;
  *height = (int) info.output_height;
  jpeg_finish_decompress (&info);
  jpeg_destroy_decompress (&info);
  if (rotate)
    rotate_180 (output, (size_t) *width * (size_t) *height, color ? 3 : 1);
  if (lineart)
    {
      size_t y, x, packed_row = ((size_t) *width + 7) / 8;
      /* SANE lineart is MSB first, with 1 = black and 0 = white.
         Pack in place; destination bytes never overwrite unread pixels. */
      for (y = 0; y < (size_t) *height; y++)
        for (x = 0; x < packed_row; x++)
          {
            unsigned int bit;
            uint8_t byte = 0;
            for (bit = 0; bit < 8 && x * 8 + bit < (size_t) *width; bit++)
              if (output[y * row_bytes + x * 8 + bit] < 128)
                byte |= 0x80 >> bit;
            output[y * packed_row + x] = byte;
          }
      output_size = packed_row * (size_t) *height;
    }
  *pixels = output;
  *size = output_size;
  return SANE_STATUS_GOOD;
}

static void
free_device (Device *device)
{
  if (!device) return;
  free ((void *) device->sane.name);
  free ((void *) device->sane.model);
  free (device);
}

/* Add the logical devices of one discovered scanner, named after address. */
static SANE_Status
attach_device (const SsDevice *protocol, const char *address)
{
  Device *device;
  int path;
  for (device = devices; device; device = device->next)
    if (!strcmp (device->protocol.ip, protocol->ip))
      return SANE_STATUS_GOOD; /* Already listed by an earlier setting. */
  /* Prepend in reverse order so ADF is the default and is listed first. */
  for (path = SS_FEED_RETURN; path >= SS_FEED_ADF; path--)
    {
      SsFeed feed = (SsFeed) path;
      char name[128], model[128];
      if (feed == SS_FEED_RETURN && !config_return_path)
        continue;
      device = calloc (1, sizeof (*device));
      if (!device) return SANE_STATUS_NO_MEM;
      /* The dll backend prepends "scansnap:" to this backend-local name. */
      snprintf (name, sizeof (name), "net:%s:%s", address,
                feed == SS_FEED_ADF ? "adf" : "return");
      snprintf (model, sizeof (model), "ScanSnap iX1300 %s",
                feed == SS_FEED_ADF ? "ADF" : "Return Path");
      device->sane.name = copy_string (name);
      device->sane.vendor = "PFU";
      device->sane.model = copy_string (model);
      device->sane.type = "sheetfed scanner";
      if (!device->sane.name || !device->sane.model)
        {
          free_device (device);
          return SANE_STATUS_NO_MEM;
        }
      device->protocol = *protocol;
      device->feed = feed;
      device->rotate = config_rotate[feed];
      device->next = devices;
      devices = device;
      device_count++;
    }
  return SANE_STATUS_GOOD;
}

/* Attach the scanner at an IPv4 address, or with "auto" every scanner that
   answers a broadcast search of the local networks. */
static SANE_Status
attach_target (const char *target)
{
  SsDevice found[MAX_TARGETS];
  char error[MAX_ERROR];
  int count, index;
  if (strcmp (target, "auto"))
    {
      if (ss_discover (target, &found[0], error, sizeof (error)) < 0)
        {
          DBG (1, "attach_target: %s\n", error);
          return SANE_STATUS_IO_ERROR;
        }
      return attach_device (&found[0], target);
    }
  count = ss_discover_all (found, MAX_TARGETS, error, sizeof (error));
  if (count < 0)
    {
      DBG (1, "attach_target: %s\n", error);
      return SANE_STATUS_IO_ERROR;
    }
  DBG (1, "attach_target: %d scanner(s) answered the broadcast search\n", count);
  for (index = 0; index < count; index++)
    if (attach_device (&found[index], found[index].ip) != SANE_STATUS_GOOD)
      return SANE_STATUS_NO_MEM;
  return SANE_STATUS_GOOD;
}

/* Split "keyword value..." into its keyword and the rest; returns the rest,
   or NULL when line does not start with keyword followed by whitespace. */
static char *
config_argument (char *line, const char *keyword)
{
  size_t length = strlen (keyword);
  if (strncmp (line, keyword, length) || !isspace ((unsigned char) line[length]))
    return NULL;
  line += length;
  while (isspace ((unsigned char) *line)) line++;
  return *line ? line : NULL;
}

/* "rotate adf 180", "rotate return 0", and so on. */
static int
parse_rotate (char *text)
{
  char path[16], angle[16], extra;
  int feed;
  if (sscanf (text, "%15s %15s %c", path, angle, &extra) != 2)
    return -1;
  if (!strcmp (path, "adf"))
    feed = SS_FEED_ADF;
  else if (!strcmp (path, "return"))
    feed = SS_FEED_RETURN;
  else
    return -1;
  if (!strcmp (angle, "180"))
    config_rotate[feed] = SANE_TRUE;
  else if (!strcmp (angle, "0"))
    config_rotate[feed] = SANE_FALSE;
  else
    return -1;
  return 0;
}

static int
parse_return_path (const char *text)
{
  if (!strcmp (text, "yes"))
    config_return_path = SANE_TRUE;
  else if (!strcmp (text, "no"))
    config_return_path = SANE_FALSE;
  else
    return -1;
  return 0;
}

static void
read_config (void)
{
  FILE *file = sanei_config_open (SCANSNAP_CONFIG_FILE);
  char line[PATH_MAX], targets[MAX_TARGETS][64];
  size_t target_count = 0, index;
  if (!file)
    {
      DBG (1, "read_config: %s was not found; no devices configured\n",
           SCANSNAP_CONFIG_FILE);
      return;
    }
  while (sanei_config_read (line, sizeof (line), file))
    {
      char *text = line, *end, *argument;
      while (isspace ((unsigned char) *text)) text++;
      if (!*text || *text == '#') continue;
      end = text + strlen (text);
      while (end > text && isspace ((unsigned char) end[-1])) *--end = '\0';
      if ((argument = config_argument (text, "net")))
        {
          if (target_count == MAX_TARGETS || strlen (argument) >= sizeof (targets[0]))
            DBG (1, "read_config: ignored scanner: %s\n", argument);
          else
            snprintf (targets[target_count++], sizeof (targets[0]), "%s", argument);
        }
      else if ((argument = config_argument (text, "rotate")))
        {
          if (parse_rotate (argument) < 0)
            DBG (1, "read_config: expected \"rotate adf|return 0|180\": %s\n", text);
        }
      else if ((argument = config_argument (text, "return-path")))
        {
          if (parse_return_path (argument) < 0)
            DBG (1, "read_config: expected \"return-path yes|no\": %s\n", text);
        }
      else
        DBG (1, "read_config: ignored line: %s\n", text);
    }
  fclose (file);
  /* Attach after reading every setting so their order in the file is free. */
  for (index = 0; index < target_count; index++)
    attach_target (targets[index]);
}

SANE_Status
sane_init (SANE_Int *version_code, SANE_Auth_Callback __sane_unused__ authorize)
{
  DBG_INIT ();
  if (version_code)
    *version_code = SANE_VERSION_CODE (SANE_CURRENT_MAJOR, SANE_CURRENT_MINOR, BUILD);
  if (!initialized)
    {
      initialized = SANE_TRUE;
      read_config ();
    }
  DBG (1, "sane_init: ScanSnap backend, %lu logical devices\n",
       (unsigned long) device_count);
  return SANE_STATUS_GOOD;
}

void
sane_exit (void)
{
  Device *next;
  while (devices)
    {
      next = devices->next;
      free_device (devices);
      devices = next;
    }
  free (device_list);
  device_list = NULL;
  device_count = 0;
  config_rotate[SS_FEED_ADF] = config_rotate[SS_FEED_RETURN] = SANE_FALSE;
  config_return_path = SANE_TRUE;
  initialized = SANE_FALSE;
}

SANE_Status
sane_get_devices (const SANE_Device ***list, SANE_Bool __sane_unused__ local_only)
{
  Device *device;
  size_t index = 0;
  free (device_list);
  device_list = calloc (device_count + 1, sizeof (*device_list));
  if (!device_list) return SANE_STATUS_NO_MEM;
  for (device = devices; device; device = device->next)
    device_list[index++] = &device->sane;
  *list = device_list;
  return SANE_STATUS_GOOD;
}

static void
option (SANE_Option_Descriptor *descriptor, const char *name, const char *title,
        const char *description, SANE_Value_Type type, SANE_Unit unit,
        SANE_Int size, SANE_Int cap)
{
  memset (descriptor, 0, sizeof (*descriptor));
  descriptor->name = name;
  descriptor->title = title;
  descriptor->desc = description;
  descriptor->type = type;
  descriptor->unit = unit;
  descriptor->size = size;
  descriptor->cap = cap;
}

static void
init_options (Handle *handle)
{
  SANE_Option_Descriptor *o = handle->options;
  option (&o[OPT_NUM_OPTS], SANE_NAME_NUM_OPTIONS, "Number of options", "",
          SANE_TYPE_INT, SANE_UNIT_NONE, sizeof (SANE_Word), SANE_CAP_SOFT_DETECT);
  option (&o[OPT_STANDARD_GROUP], SANE_NAME_STANDARD, "Scan Mode", "",
          SANE_TYPE_GROUP, SANE_UNIT_NONE, 0, 0);
  option (&o[OPT_SOURCE], SANE_NAME_SCAN_SOURCE, "Scan source",
          "Select simplex or duplex scanning on this device's feed path.",
          SANE_TYPE_STRING, SANE_UNIT_NONE, 32,
          SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT);
  o[OPT_SOURCE].constraint_type = SANE_CONSTRAINT_STRING_LIST;
  o[OPT_SOURCE].constraint.string_list = source_list;
  option (&o[OPT_MODE], SANE_NAME_SCAN_MODE, "Scan mode", "Image color mode.",
          SANE_TYPE_STRING, SANE_UNIT_NONE, 16,
          SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT);
  o[OPT_MODE].constraint_type = SANE_CONSTRAINT_STRING_LIST;
  o[OPT_MODE].constraint.string_list = mode_list;
  option (&o[OPT_RESOLUTION], SANE_NAME_SCAN_RESOLUTION, "Scan resolution",
          "Scan resolution in dots per inch.", SANE_TYPE_INT, SANE_UNIT_DPI,
          sizeof (SANE_Word), SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT);
  o[OPT_RESOLUTION].constraint_type = SANE_CONSTRAINT_WORD_LIST;
  o[OPT_RESOLUTION].constraint.word_list = resolution_list;
  option (&o[OPT_ENHANCEMENT_GROUP], SANE_NAME_ENHANCEMENT, "Enhancement", "",
          SANE_TYPE_GROUP, SANE_UNIT_NONE, 0, 0);
  option (&o[OPT_AUTO_SIZE], "automatic-page-size", "Automatic page size",
          "Use the scanner's automatic document length and cropping.",
          SANE_TYPE_BOOL, SANE_UNIT_NONE, sizeof (SANE_Word), SANE_CAP_SOFT_DETECT);
  option (&o[OPT_ROTATE], "rotate", "Rotate 180 degrees",
          "Rotate every page by 180 degrees, for sheets loaded with their "
          "bottom edge first. The default comes from scansnap.conf.",
          SANE_TYPE_BOOL, SANE_UNIT_NONE, sizeof (SANE_Word),
          SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT);
  option (&o[OPT_DEVICE_GROUP], SANE_NAME_ADVANCED, "Device", "",
          SANE_TYPE_GROUP, SANE_UNIT_NONE, 0, 0);
  option (&o[OPT_FEED_PATH], "feed-path", "Feed path", "Physical paper path.",
          SANE_TYPE_STRING, SANE_UNIT_NONE, 16, SANE_CAP_SOFT_DETECT);
  option (&o[OPT_SERIAL], "serial-number", "Serial number", "Scanner serial number.",
          SANE_TYPE_STRING, SANE_UNIT_NONE, 16, SANE_CAP_SOFT_DETECT);
  snprintf (handle->source, sizeof (handle->source), "%s", source_list[0]);
  snprintf (handle->mode, sizeof (handle->mode), "%s", mode_list[0]);
  handle->resolution = 300;
  handle->auto_size = SANE_TRUE;
  handle->rotate = handle->device ? handle->device->rotate : SANE_FALSE;
}

SANE_Status
sane_open (SANE_String_Const name, SANE_Handle *out)
{
  Device *device;
  Handle *handle;
  if (!out) return SANE_STATUS_INVAL;
  for (device = devices; device; device = device->next)
    if ((!name || !*name) || !strcmp (device->sane.name, name)) break;
  if (!device) return SANE_STATUS_INVAL;
  if (device->open) return SANE_STATUS_DEVICE_BUSY;
  handle = calloc (1, sizeof (*handle));
  if (!handle) return SANE_STATUS_NO_MEM;
  handle->device = device;
  device->open = 1;
  init_options (handle);
  *out = handle;
  return SANE_STATUS_GOOD;
}

static void
clear_images (Handle *handle)
{
  if (handle->current && handle->current != handle->front
      && handle->current != handle->back)
    free (handle->current);
  free (handle->front);
  free (handle->back);
  handle->front = handle->back = handle->current = NULL;
  handle->front_size = handle->back_size = handle->current_size = 0;
  handle->back_width = handle->back_height = 0;
  handle->offset = 0;
  handle->scanning = 0;
}

void
sane_close (SANE_Handle opaque)
{
  Handle *handle = opaque;
  if (!handle) return;
  clear_images (handle);
  if (handle->job_active)
    {
      ss_session_close (&handle->session);
      handle->job_active = 0;
    }
  handle->device->open = 0;
  free (handle);
}

const SANE_Option_Descriptor *
sane_get_option_descriptor (SANE_Handle opaque, SANE_Int index)
{
  Handle *handle = opaque;
  if (!handle || index < 0 || index >= NUM_OPTIONS) return NULL;
  return &handle->options[index];
}

SANE_Status
sane_control_option (SANE_Handle opaque, SANE_Int index, SANE_Action action,
                     void *value, SANE_Int *info)
{
  Handle *handle = opaque;
  SANE_Status status;
  SANE_Int changes = 0;
  if (info) *info = 0;
  if (!handle || !value || index < 0 || index >= NUM_OPTIONS)
    return SANE_STATUS_INVAL;
  if (handle->scanning) return SANE_STATUS_DEVICE_BUSY;
  if (action == SANE_ACTION_GET_VALUE)
    {
      switch (index)
        {
        case OPT_NUM_OPTS: *(SANE_Word *) value = NUM_OPTIONS; break;
        case OPT_SOURCE: strcpy (value, handle->source); break;
        case OPT_MODE: strcpy (value, handle->mode); break;
        case OPT_RESOLUTION: *(SANE_Word *) value = handle->resolution; break;
        case OPT_AUTO_SIZE: *(SANE_Word *) value = handle->auto_size; break;
        case OPT_ROTATE: *(SANE_Word *) value = handle->rotate; break;
        case OPT_FEED_PATH:
          strcpy (value, handle->device->feed == SS_FEED_ADF ? "ADF" : "Return");
          break;
        case OPT_SERIAL: strcpy (value, handle->device->protocol.serial); break;
        default: return SANE_STATUS_INVAL;
        }
      return SANE_STATUS_GOOD;
    }
  if (action != SANE_ACTION_SET_VALUE
      || !(handle->options[index].cap & SANE_CAP_SOFT_SELECT))
    return SANE_STATUS_INVAL;
  if (handle->job_active || handle->back) return SANE_STATUS_DEVICE_BUSY;
  status = sanei_constrain_value (&handle->options[index], value, &changes);
  if (status != SANE_STATUS_GOOD) return status;
  switch (index)
    {
    case OPT_SOURCE:
      strcpy (handle->source, value);
      changes |= SANE_INFO_RELOAD_PARAMS;
      break;
    case OPT_MODE:
      strcpy (handle->mode, value);
      changes |= SANE_INFO_RELOAD_PARAMS;
      break;
    case OPT_RESOLUTION: handle->resolution = *(SANE_Word *) value; break;
    case OPT_ROTATE: handle->rotate = *(SANE_Word *) value ? SANE_TRUE : SANE_FALSE; break;
    default: return SANE_STATUS_INVAL;
    }
  if (info) *info = changes;
  return SANE_STATUS_GOOD;
}

SANE_Status
sane_get_parameters (SANE_Handle opaque, SANE_Parameters *parameters)
{
  Handle *handle = opaque;
  if (!handle || !parameters) return SANE_STATUS_INVAL;
  if (handle->scanning)
    *parameters = handle->params;
  else
    {
      memset (parameters, 0, sizeof (*parameters));
      parameters->format = !strcmp (handle->mode, SANE_VALUE_SCAN_MODE_COLOR)
        ? SANE_FRAME_RGB : SANE_FRAME_GRAY;
      parameters->last_frame = SANE_TRUE;
      parameters->depth = !strcmp (handle->mode, SANE_VALUE_SCAN_MODE_LINEART)
        ? 1 : 8;
      parameters->lines = -1;
    }
  return SANE_STATUS_GOOD;
}

static void
set_current (Handle *handle, uint8_t *pixels, size_t size, int width, int height)
{
  handle->current = pixels;
  handle->current_size = size;
  handle->offset = 0;
  handle->width = width;
  handle->height = height;
  handle->scanning = 1;
  handle->params.format = !strcmp (handle->mode, SANE_VALUE_SCAN_MODE_COLOR)
    ? SANE_FRAME_RGB : SANE_FRAME_GRAY;
  /* Each duplex side is a complete image.  A false last_frame is reserved
     for multiple frames that make up one image, such as separate RGB planes. */
  handle->params.last_frame = SANE_TRUE;
  handle->params.bytes_per_line =
    !strcmp (handle->mode, SANE_VALUE_SCAN_MODE_LINEART) ? (width + 7) / 8
    : handle->params.format == SANE_FRAME_RGB ? width * 3 : width;
  handle->params.pixels_per_line = width;
  handle->params.lines = height;
  handle->params.depth = !strcmp (handle->mode, SANE_VALUE_SCAN_MODE_LINEART)
    ? 1 : 8;
}

SANE_Status
sane_start (SANE_Handle opaque)
{
  Handle *handle = opaque;
  SsImage front_jpeg, back_jpeg;
  SANE_Status status;
  char error[MAX_ERROR];
  int result, front_width, front_height, back_width = 0, back_height = 0;

  if (!handle) return SANE_STATUS_INVAL;
  if (handle->scanning) return SANE_STATUS_DEVICE_BUSY;
  if (handle->back)
    {
      uint8_t *back = handle->back;
      size_t size = handle->back_size;
      handle->back = NULL;
      handle->back_size = 0;
      int width = handle->back_width;
      int height = handle->back_height;
      handle->back_width = handle->back_height = 0;
      set_current (handle, back, size, width, height);
      return SANE_STATUS_GOOD;
    }
  clear_images (handle);
  handle->duplex = !strcmp (handle->source, "ADF Duplex");
  if (handle->device->feed == SS_FEED_ADF)
    {
      if (!handle->job_active)
        {
          if (ss_session_open (&handle->session, &handle->device->protocol,
                               error, sizeof (error)) < 0)
            {
              DBG (1, "sane_start: %s\n", error);
              return SANE_STATUS_DEVICE_BUSY;
            }
          result = ss_scan_begin (&handle->session, SS_FEED_ADF,
                                  handle->duplex, error, sizeof (error));
          if (result < 0)
            {
              DBG (1, "sane_start: %s\n", error);
              ss_session_close (&handle->session);
              if (result == -2) return SANE_STATUS_COVER_OPEN;
              if (result == -3) return SANE_STATUS_NO_DOCS;
              return SANE_STATUS_IO_ERROR;
            }
          handle->job_active = 1;
        }
      result = ss_scan_next (&handle->session, handle->duplex, &front_jpeg,
                             &back_jpeg, error, sizeof (error));
      if (result == 1)
        {
          ss_session_close (&handle->session);
          handle->job_active = 0;
          return SANE_STATUS_NO_DOCS;
        }
      if (result < 0)
        {
          DBG (1, "sane_start: %s\n", error);
          ss_session_close (&handle->session);
          handle->job_active = 0;
          return SANE_STATUS_IO_ERROR;
        }
    }
  else
    {
      SsSession session;
      if (ss_session_open (&session, &handle->device->protocol,
                           error, sizeof (error)) < 0)
        {
          DBG (1, "sane_start: %s\n", error);
          return SANE_STATUS_DEVICE_BUSY;
        }
      result = ss_scan (&session, handle->device->feed, handle->duplex,
                        &front_jpeg, &back_jpeg, error, sizeof (error));
      ss_session_close (&session);
      if (result < 0)
        {
          DBG (1, "sane_start: %s\n", error);
          if (result == -2) return SANE_STATUS_COVER_OPEN;
          if (result == -3) return SANE_STATUS_NO_DOCS;
          return SANE_STATUS_IO_ERROR;
        }
    }
  status = decode_jpeg (&front_jpeg, handle->mode, handle->rotate,
                        &handle->front, &handle->front_size,
                        &front_width, &front_height, error, sizeof (error));
  ss_image_free (&front_jpeg);
  if (status == SANE_STATUS_GOOD && handle->duplex)
    {
      status = decode_jpeg (&back_jpeg, handle->mode, handle->rotate,
                            &handle->back, &handle->back_size,
                            &back_width, &back_height, error, sizeof (error));
      if (status == SANE_STATUS_GOOD)
        {
          handle->back_width = back_width;
          handle->back_height = back_height;
        }
    }
  ss_image_free (&back_jpeg);
  if (status != SANE_STATUS_GOOD)
    {
      DBG (1, "sane_start: %s\n", error);
      clear_images (handle);
      if (handle->job_active)
        {
          ss_session_close (&handle->session);
          handle->job_active = 0;
        }
      return status;
    }
  set_current (handle, handle->front, handle->front_size,
               front_width, front_height);
  return SANE_STATUS_GOOD;
}

SANE_Status
sane_read (SANE_Handle opaque, SANE_Byte *data, SANE_Int max_length,
           SANE_Int *length)
{
  Handle *handle = opaque;
  size_t remaining, count;
  if (!handle || !data || !length || max_length < 0) return SANE_STATUS_INVAL;
  *length = 0;
  if (!handle->scanning) return SANE_STATUS_INVAL;
  remaining = handle->current_size - handle->offset;
  if (!remaining)
    {
      uint8_t *finished = handle->current;
      handle->scanning = 0;
      handle->current = NULL;
      handle->current_size = handle->offset = 0;
      if (finished == handle->front)
        {
          free (handle->front);
          handle->front = NULL;
          handle->front_size = 0;
        }
      else
        free (finished);
      return SANE_STATUS_EOF;
    }
  count = remaining < (size_t) max_length ? remaining : (size_t) max_length;
  memcpy (data, handle->current + handle->offset, count);
  handle->offset += count;
  *length = (SANE_Int) count;
  return SANE_STATUS_GOOD;
}

void
sane_cancel (SANE_Handle opaque)
{
  Handle *handle = opaque;
  if (handle)
    {
      clear_images (handle);
      if (handle->job_active)
        {
          ss_session_close (&handle->session);
          handle->job_active = 0;
        }
    }
}

SANE_Status
sane_set_io_mode (SANE_Handle opaque, SANE_Bool non_blocking)
{
  if (!opaque) return SANE_STATUS_INVAL;
  return non_blocking ? SANE_STATUS_UNSUPPORTED : SANE_STATUS_GOOD;
}

SANE_Status
sane_get_select_fd (SANE_Handle __sane_unused__ opaque,
                    SANE_Int __sane_unused__ *fd)
{
  return SANE_STATUS_UNSUPPORTED;
}
