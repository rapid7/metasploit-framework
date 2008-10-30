/*
 * tableinitcmtemplate.c - template for initialising lookup tables for
 * translation from a colour map to true colour.
 *
 * This file shouldn't be compiled.  It is included multiple times by
 * translate.c, each time with a different definition of the macro OUT.
 * For each value of OUT, this file defines a function which allocates an
 * appropriately sized lookup table and initialises it.
 *
 * I know this code isn't nice to read because of all the macros, but
 * efficiency is important here.
 */

#if !defined(OUT)
#error "This file shouldn't be compiled."
#error "It is included as part of translate.c"
#endif

#define OUT_T CONCAT2E(CARD,OUT)
#define SwapOUT(x) CONCAT2E(Swap,OUT) (x)
#define rfbInitColourMapSingleTableOUT \
				CONCAT2E(rfbInitColourMapSingleTable,OUT)

// THIS CODE HAS BEEN MODIFIED FROM THE ORIGINAL UNIX SOURCE
// TO WORK FOR WINVNC.  THE PALETTE SHOULD REALLY BE RETRIEVED
// FROM THE VNCDESKTOP OBJECT, RATHER THAN FROM THE OS DIRECTLY

static void
rfbInitColourMapSingleTableOUT (char **table,
								rfbPixelFormat *in,
								rfbPixelFormat *out)
{
	//vnclog.Print(LL_ALL, VNCLOG("rfbInitColourMapSingleTable called\n"));

	// ALLOCATE SPACE FOR COLOUR TABLE

    int nEntries = 1 << in->bitsPerPixel;

	// Allocate the table
    if (*table) free(*table);
    *table = (char *)malloc(nEntries * sizeof(OUT_T));
	if (*table == NULL)
	{
		//vnclog.Print(LL_INTERR, VNCLOG("failed to allocate translation table\n"));
		return;
	}

	// Obtain the system palette
	HDC hDC = GetDC(NULL);
	PALETTEENTRY palette[256];
  UINT entries = ::GetSystemPaletteEntries(hDC,	0, 256, palette);
	//vnclog.Print(LL_INTINFO, VNCLOG("got %u palette entries\n"), GetLastError());
	ReleaseDC(NULL, hDC);

  // - Set the rest of the palette to something nasty but usable
  unsigned int i;
  for (i=entries;i<256;i++) {
    palette[i].peRed = i % 2 ? 255 : 0;
    palette[i].peGreen = i/2 % 2 ? 255 : 0;
    palette[i].peBlue = i/4 % 2 ? 255 : 0;
  }

	// COLOUR TRANSLATION

	// We now have the colour table intact.  Map it into a translation table
  int r, g, b;
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
#if (OUT != 8)
		if (out->bigEndian != in->bigEndian)
		{
			t[i] = SwapOUT(t[i]);
		}
#endif
	}

	//vnclog.Print(LL_ALL, VNCLOG("rfbInitColourMapSingleTable done\n"));
}

#undef OUT_T
#undef SwapOUT
#undef rfbInitColourMapSingleTableOUT
