/*
 * tabletranstemplate.c - template for translation using lookup tables.
 *
 * This file shouldn't be compiled.  It is included multiple times by
 * translate.c, each time with different definitions of the macros INBPP and OUTBPP.
 *
 * For each pair of values INBPP and OUTBPP, this file defines two functions for
 * translating a given rectangle of pixel data.  One uses a single lookup
 * table, and the other uses three separate lookup tables for the red, green
 * and blue values.
 *
 * I know this code isn't nice to read because of all the macros, but
 * efficiency is important here.
 */

#if !defined(INBPP) || !defined(OUTBPP)
#error "This file shouldn't be compiled."
#error "It is included as part of translate.c"
#endif

#define IN_T CONCAT2E(CARD,INBPP)
#define OUT_T CONCAT2E(CARD,OUTBPP)
#define rfbTranslateWithSingleTableINtoOUT \
				CONCAT4E(rfbTranslateWithSingleTable,INBPP,to,OUTBPP)
#define rfbTranslateWithRGBTablesINtoOUT \
				CONCAT4E(rfbTranslateWithRGBTables,INBPP,to,OUTBPP)

/*
 * rfbTranslateWithSingleTableINtoOUT translates a rectangle of pixel data
 * using a single lookup table.
 */

static void
rfbTranslateWithSingleTableINtoOUT (char *table, rfbPixelFormat *in,
				    rfbPixelFormat *out,
				    char *iptr, char *optr,
				    int bytesBetweenInputLines,
				    int width, int height)
{
    IN_T *ip = (IN_T *)iptr;
    OUT_T *op = (OUT_T *)optr;
    int ipextra = bytesBetweenInputLines / sizeof(IN_T) - width;
    OUT_T *opLineEnd;
    OUT_T *t = (OUT_T *)table;

    while (height > 0) {
	opLineEnd = op + width;

	while (op < opLineEnd) {
	    *(op++) = t[*(ip++)];
	}

	ip += ipextra;
	height--;
    }
}


/*
 * rfbTranslateWithRGBTablesINtoOUT translates a rectangle of pixel data
 * using three separate lookup tables for the red, green and blue values.
 */

static void
rfbTranslateWithRGBTablesINtoOUT (char *table, rfbPixelFormat *in,
				  rfbPixelFormat *out,
				  char *iptr, char *optr,
				  int bytesBetweenInputLines,
				  int width, int height)
{
    IN_T *ip = (IN_T *)iptr;
    OUT_T *op = (OUT_T *)optr;
    int ipextra = bytesBetweenInputLines / sizeof(IN_T) - width;
    OUT_T *opLineEnd;
    OUT_T *redTable = (OUT_T *)table;
    OUT_T *greenTable = redTable + in->redMax + 1;
    OUT_T *blueTable = greenTable + in->greenMax + 1;
    IN_T in_pix;
    OUT_T out_pix;

    while (height > 0) {
	opLineEnd = op + width;

	while (op < opLineEnd) {
	    in_pix = *ip++;
	    out_pix  = redTable[(in_pix >> in->redShift) & in->redMax];
	    out_pix |= greenTable[(in_pix >> in->greenShift) & in->greenMax];
	    out_pix |= blueTable[(in_pix >> in->blueShift) & in->blueMax];
	    *op++ = out_pix;
	}
	ip += ipextra;
	height--;
    }
}

#undef IN_T
#undef OUT_T
#undef rfbTranslateWithSingleTableINtoOUT
#undef rfbTranslateWithRGBTablesINtoOUT
