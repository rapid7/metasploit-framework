/*
 * tableinitcmtemplate.c - template for initialising lookup tables for
 * translation from a colour map to true colour.
 *
 * This file shouldn't be compiled.  It is included multiple times by
 * translate.c, each time with a different definition of the macro OUTBPP.
 * For each value of OUTBPP, this file defines a function which allocates an
 * appropriately sized lookup table and initialises it.
 *
 * I know this code isn't nice to read because of all the macros, but
 * efficiency is important here.
 */

#if !defined(OUTBPP)
#error "This file shouldn't be compiled."
#error "It is included as part of translate.c"
#endif

#define OUT_T CONCAT2E(CARD,OUTBPP)
#define SwapOUT(x) CONCAT2E(Swap,OUTBPP) (x)
#define rfbInitColourMapSingleTableOUT \
				CONCAT2E(rfbInitColourMapSingleTable,OUTBPP)

// THIS CODE HAS BEEN MODIFIED FROM THE ORIGINAL UNIX SOURCE
// TO WORK FOR WINVNC.  THE PALETTE SHOULD REALLY BE RETRIEVED
// FROM THE VNCDESKTOP OBJECT, RATHER THAN FROM THE OS DIRECTLY

static void
rfbInitColourMapSingleTableOUT (char **table,
								rfbPixelFormat *in,
								rfbPixelFormat *out)
{
	// ALLOCATE SPACE FOR COLOUR TABLE

    int nEntries = 1 << in->bitsPerPixel;

	// Allocate the table
    if (*table) free(*table);
    *table = (char *)malloc(nEntries * sizeof(OUT_T));
	if (*table == NULL)
	{
		return;
	}

	// Obtain the system palette
	HDC hDC = GetDC(NULL);
	PALETTEENTRY palette[256];
	if (GetSystemPaletteEntries(hDC,
		0, 256, palette) == 0)
	{
		ReleaseDC(NULL, hDC);
		return;
	}
	ReleaseDC(NULL, hDC);

	// COLOUR TRANSLATION

	// We now have the colour table intact.  Map it into a translation table
    int i, r, g, b;
    OUT_T *t = (OUT_T *)*table;

    for (i = 0; i < nEntries; i++)
	{
		// Split down the RGB data
		r = palette[i].peRed;
		g = palette[i].peGreen;
		b = palette[i].peBlue;

		// Now translate it
		t[i] = ((((r * out->redMax + 127) / 255) << out->redShift) |
			(((g * out->greenMax + 127) / 255) << out->greenShift) |
			(((b * out->blueMax + 127) / 255) << out->blueShift));
#if (OUTBPP != 8)
		if (out->bigEndian != in->bigEndian)
		{
			t[i] = SwapOUT(t[i]);
		}
#endif
	}

}

#undef OUT_T
#undef SwapOUT
#undef rfbInitColourMapSingleTableOUT
