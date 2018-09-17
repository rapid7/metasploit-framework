/* from https://github.com/mdornseif/didentd */
/* public domain
 * BASE64 on stdin -> converted data on stdout */

/* arbitrary data on stdin -> BASE64 data on stdout
 * UNIX's newline convention is used, i.e. one ASCII control-j (10 decimal).
 *
 * public domain
 */

/* Hacked by drt@un.bewaff.net to be a library function working on memory blocks
 *
 */

static unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64decode(char *dest, const char *src, int l)
{
  static char inalphabet[256], decoder[256];
  static bool table_initialized = false;
  int i, bits, c, char_count;
  int rpos;
  int wpos = 0;

  if (!table_initialized) {
    for (i = (sizeof alphabet) - 1; i >= 0; i--) {
      inalphabet[alphabet[i]] = 1;
      decoder[alphabet[i]] = i;
    }
    table_initialized = true;
  }

  char_count = 0;
  bits = 0;
  for (rpos = 0; rpos < l; rpos++) {
    c = src[rpos];

    if (c == '=') {
      break;
    }

    if (c > 255 || !inalphabet[c]) {
      return -1;
    }

    bits += decoder[c];
    char_count++;
    if (char_count < 4) {
      bits <<= 6;
    } else {
      dest[wpos++] = bits >> 16;
      dest[wpos++] = (bits >> 8) & 0xff;
      dest[wpos++] = bits & 0xff;
      bits = 0;
      char_count = 0;
    }
  }

  switch (char_count) {
  case 1:
    return -1;
    break;
  case 2:
    dest[wpos++] = bits >> 10;
    break;
  case 3:
    dest[wpos++] = bits >> 16;
    dest[wpos++] = (bits >> 8) & 0xff;
    break;
  }

  return wpos;
}

int base64encode(char *dest, const char *src, int l)
{
  int bits, c, char_count;
  int rpos;
  int wpos = 0;

  char_count = 0;
  bits = 0;

  for (rpos = 0; rpos < l; rpos++) {
    c = src[rpos];

    bits += c;
    char_count++;
    if (char_count < 3) {
      bits <<= 8;
    } else {
      dest[wpos++] = alphabet[bits >> 18];
      dest[wpos++] = alphabet[(bits >> 12) & 0x3f];
      dest[wpos++] = alphabet[(bits >> 6) & 0x3f];
      dest[wpos++] = alphabet[bits & 0x3f];
      bits = 0;
      char_count = 0;
    }
  }

  if (char_count != 0) {
    bits <<= 16 - (8 * char_count);
    dest[wpos++] = alphabet[bits >> 18];
    dest[wpos++] = alphabet[(bits >> 12) & 0x3f];
    if (char_count == 1) {
      dest[wpos++] = '=';
      dest[wpos++] = '=';
    } else {
      dest[wpos++] = alphabet[(bits >> 6) & 0x3f];
      dest[wpos++] = '=';
    }
  }
  return wpos;
}