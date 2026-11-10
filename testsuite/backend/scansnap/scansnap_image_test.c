/* SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception */
/* Synthetic JPEGs exercise the production decoder and SANE page delivery. */
#define BACKEND_NAME scansnap
#include "../../../backend/scansnap.c"

#define CHECK(expr) do { if (!(expr)) { \
  fprintf (stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
  exit (1); } } while (0)

static SsImage
make_jpeg (int width, int height)
{
  struct jpeg_compress_struct info;
  struct jpeg_error_mgr error;
  unsigned char *data = NULL;
  unsigned long size = 0;
  unsigned char row[51];
  SsImage image = { 0 };
  int x;
  info.err = jpeg_std_error (&error);
  jpeg_create_compress (&info);
  jpeg_mem_dest (&info, &data, &size);
  info.image_width = width;
  info.image_height = height;
  info.input_components = 3;
  info.in_color_space = JCS_RGB;
  jpeg_set_defaults (&info);
  jpeg_set_quality (&info, 100, TRUE);
  jpeg_start_compress (&info, TRUE);
  while (info.next_scanline < info.image_height)
    {
      JSAMPROW scanline = row;
      for (x = 0; x < width; x++)
        memset (row + x * 3, (x + info.next_scanline) % 2 ? 255 : 0, 3);
      jpeg_write_scanlines (&info, &scanline, 1);
    }
  jpeg_finish_compress (&info);
  jpeg_destroy_compress (&info);
  image.data = data;
  image.length = size;
  return image;
}

static void
check_mode (const char *mode, int width)
{
  Handle handle = { 0 };
  SANE_Parameters params;
  SsImage jpeg = make_jpeg (width, 3);
  unsigned char *pixels, result[153];
  size_t size, offset = 0;
  char message[MAX_ERROR], value[16];
  int w, h, y, x;
  SANE_Int changes, length;
  int color = !strcmp (mode, SANE_VALUE_SCAN_MODE_COLOR);
  int lineart = !strcmp (mode, SANE_VALUE_SCAN_MODE_LINEART);
  int stride = lineart ? (width + 7) / 8 : width * (color ? 3 : 1);
  init_options (&handle);
  strcpy (value, mode);
  CHECK (sane_control_option (&handle, OPT_MODE, SANE_ACTION_SET_VALUE,
                             value, &changes) == SANE_STATUS_GOOD);
  CHECK (changes & SANE_INFO_RELOAD_PARAMS);
  CHECK (sane_get_parameters (&handle, &params) == SANE_STATUS_GOOD);
  CHECK (params.format == (color ? SANE_FRAME_RGB : SANE_FRAME_GRAY));
  CHECK (params.depth == (lineart ? 1 : 8));
  CHECK (params.lines == -1);
  CHECK (decode_jpeg (&jpeg, mode, SANE_FALSE, &pixels, &size, &w, &h,
                     message, sizeof (message)) == SANE_STATUS_GOOD);
  ss_image_free (&jpeg);
  CHECK (w == width && h == 3 && size == (size_t) stride * 3);
  set_current (&handle, pixels, size, w, h);
  CHECK (sane_get_parameters (&handle, &params) == SANE_STATUS_GOOD);
  CHECK (params.bytes_per_line == stride && params.pixels_per_line == width);
  CHECK (params.lines == 3 && params.depth == (lineart ? 1 : 8));
  CHECK (params.format == (color ? SANE_FRAME_RGB : SANE_FRAME_GRAY));
  CHECK (params.last_frame);
  while (sane_read (&handle, result + offset, 1, &length) == SANE_STATUS_GOOD)
    offset += length;
  CHECK (offset == size);
  for (y = 0; y < 3; y++)
    for (x = 0; x < width; x++)
      {
        int white = (x + y) % 2;
        if (lineart)
          CHECK (!!(result[y * stride + x / 8] & (0x80 >> (x % 8))) == !white);
        else
          {
            int c;
            for (c = 0; c < (color ? 3 : 1); c++)
              CHECK (abs (result[y * stride + x * (color ? 3 : 1) + c]
                          - (white ? 255 : 0)) <= 2);
          }
      }
  if (lineart && width % 8)
    for (y = 0; y < 3; y++)
      CHECK (!(result[y * stride + stride - 1] & ((1 << (8 - width % 8)) - 1)));
  /* A queued duplex side keeps its original mode until consumed. */
  handle.back = malloc (1);
  CHECK (handle.back != NULL);
  CHECK (sane_control_option (&handle, OPT_MODE, SANE_ACTION_SET_VALUE,
                             value, &changes) == SANE_STATUS_DEVICE_BUSY);
  clear_images (&handle);
  handle.job_active = 1;
  CHECK (sane_control_option (&handle, OPT_MODE, SANE_ACTION_SET_VALUE,
                             value, &changes) == SANE_STATUS_DEVICE_BUSY);
  handle.job_active = 0;
}

static int
lineart_bit (const unsigned char *image, int stride, int x, int y)
{
  return !!(image[y * stride + x / 8] & (0x80 >> (x % 8)));
}

/* A rotated decode must equal the plain decode read back to front. */
static void
check_rotate (const char *mode, int width, int height)
{
  SsImage jpeg = make_jpeg (width, height);
  unsigned char *plain, *rotated;
  size_t plain_size, rotated_size;
  char message[MAX_ERROR];
  int w, h, x, y;
  int color = !strcmp (mode, SANE_VALUE_SCAN_MODE_COLOR);
  int lineart = !strcmp (mode, SANE_VALUE_SCAN_MODE_LINEART);
  int bytes = color ? 3 : 1;
  int stride = lineart ? (width + 7) / 8 : width * bytes;
  CHECK (decode_jpeg (&jpeg, mode, SANE_FALSE, &plain, &plain_size, &w, &h,
                     message, sizeof (message)) == SANE_STATUS_GOOD);
  CHECK (decode_jpeg (&jpeg, mode, SANE_TRUE, &rotated, &rotated_size, &w, &h,
                     message, sizeof (message)) == SANE_STATUS_GOOD);
  ss_image_free (&jpeg);
  CHECK (w == width && h == height && rotated_size == plain_size);
  for (y = 0; y < height; y++)
    for (x = 0; x < width; x++)
      {
        int rx = width - 1 - x, ry = height - 1 - y;
        if (lineart)
          CHECK (lineart_bit (rotated, stride, x, y)
                 == lineart_bit (plain, stride, rx, ry));
        else
          CHECK (!memcmp (rotated + y * stride + x * bytes,
                          plain + ry * stride + rx * bytes, bytes));
      }
  if (lineart && width % 8)
    for (y = 0; y < height; y++)
      CHECK (!(rotated[y * stride + stride - 1] & ((1 << (8 - width % 8)) - 1)));
  free (plain);
  free (rotated);
}

static void
check_rotate_option (void)
{
  Device device = { 0 };
  Handle handle = { 0 };
  SANE_Word value;
  SANE_Int changes;
  init_options (&handle);
  CHECK (handle.options[OPT_ROTATE].type == SANE_TYPE_BOOL);
  CHECK (handle.options[OPT_ROTATE].cap & SANE_CAP_SOFT_SELECT);
  CHECK (sane_control_option (&handle, OPT_ROTATE, SANE_ACTION_GET_VALUE,
                             &value, NULL) == SANE_STATUS_GOOD && !value);
  device.rotate = SANE_TRUE;
  handle.device = &device;
  init_options (&handle);
  CHECK (sane_control_option (&handle, OPT_ROTATE, SANE_ACTION_GET_VALUE,
                             &value, NULL) == SANE_STATUS_GOOD && value);
  value = SANE_FALSE;
  CHECK (sane_control_option (&handle, OPT_ROTATE, SANE_ACTION_SET_VALUE,
                             &value, &changes) == SANE_STATUS_GOOD);
  CHECK (!handle.rotate);
}

static void
check_config_settings (void)
{
  char text[32];
  CHECK (!config_rotate[SS_FEED_ADF] && !config_rotate[SS_FEED_RETURN]);
  CHECK (config_return_path);
  strcpy (text, "adf 180");
  CHECK (parse_rotate (text) == 0 && config_rotate[SS_FEED_ADF]);
  CHECK (!config_rotate[SS_FEED_RETURN]);
  strcpy (text, "return 180");
  CHECK (parse_rotate (text) == 0 && config_rotate[SS_FEED_RETURN]);
  strcpy (text, "adf 0");
  CHECK (parse_rotate (text) == 0 && !config_rotate[SS_FEED_ADF]);
  strcpy (text, "adf 90");
  CHECK (parse_rotate (text) < 0);
  strcpy (text, "flatbed 180");
  CHECK (parse_rotate (text) < 0);
  strcpy (text, "adf 180 extra");
  CHECK (parse_rotate (text) < 0);
  CHECK (parse_return_path ("no") == 0 && !config_return_path);
  CHECK (parse_return_path ("maybe") < 0 && !config_return_path);
  CHECK (parse_return_path ("yes") == 0 && config_return_path);
  CHECK (config_argument (strcpy (text, "rotate adf 180"), "rotate") == text + 7);
  CHECK (config_argument (strcpy (text, "rotated adf"), "rotate") == NULL);
  CHECK (config_argument (strcpy (text, "rotate   "), "rotate") == NULL);
  sane_exit ();
  CHECK (!config_rotate[SS_FEED_ADF] && !config_rotate[SS_FEED_RETURN]);
  CHECK (config_return_path);
}

int
main (void)
{
  int m, w, cases = 0;
  const int widths[] = { 1, 7, 8, 9, 17 };
  for (m = 0; mode_list[m]; m++)
    for (w = 0; w < 5; w++)
      {
        check_mode (mode_list[m], widths[w]);
        check_rotate (mode_list[m], widths[w], 3);
        check_rotate (mode_list[m], widths[w], 4);
        cases += 3;
      }
  check_rotate_option ();
  check_config_settings ();
  printf ("ScanSnap: %d offline image cases and settings checks passed\n", cases);
  return 0;
}
