/* $Xorg: Xutil.h,v 1.8 2001/02/09 02:03:39 xorgcvs Exp $ */

/***********************************************************

Copyright 1987, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.


Copyright 1987 by Digital Equipment Corporation, Maynard, Massachusetts.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of Digital not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

DIGITAL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
DIGITAL BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/
/* $XFree86: xc/lib/X11/Xutil.h,v 3.4 2001/12/14 19:54:10 dawes Exp $ */

#ifndef _XREGION_H_
#define _XREGION_H_

// - Faked defines to fool the X11 region code

#include <stdlib.h>
#include <string.h>

#define Bool int
#define Xmalloc malloc
#define Xfree free
#define Xrealloc realloc

#define NeedFunctionPrototypes 1

// - Cribbed from Xlib.h

typedef struct {
    short x, y;
} XPoint;

typedef struct {
    short x, y;
    unsigned short width, height;
} XRectangle;

//#include <Xregion/region.h>

/*
 * opaque reference to Region data type 
 */
typedef struct _XRegion *XRegion; 

/* Return values from XRectInRegion() */
 
#define RectangleOut 0
#define RectangleIn  1
#define RectanglePart 2

#ifdef __cplusplus
extern "C" {
#endif

extern int XClipBox(
#if NeedFunctionPrototypes
    XRegion		/* r */,
    XRectangle*		/* rect_return */
#endif
);

extern XRegion XCreateRegion(
#if NeedFunctionPrototypes
    void
#endif
);

extern const char *XDefaultString (void);

extern int XDestroyRegion(
#if NeedFunctionPrototypes
    XRegion		/* r */
#endif
);

extern int XEmptyRegion(
#if NeedFunctionPrototypes
    XRegion		/* r */
#endif
);

extern int XEqualRegion(
#if NeedFunctionPrototypes
    XRegion		/* r1 */,
    XRegion		/* r2 */
#endif
);

extern int XIntersectRegion(
#if NeedFunctionPrototypes
    XRegion		/* sra */,
    XRegion		/* srb */,
    XRegion		/* dr_return */
#endif
);

extern int XOffsetRegion(
#if NeedFunctionPrototypes
    XRegion		/* r */,
    int			/* dx */,
    int			/* dy */
#endif
);

extern Bool XPointInRegion(
#if NeedFunctionPrototypes
    XRegion		/* r */,
    int			/* x */,
    int			/* y */
#endif
);

extern XRegion XPolygonRegion(
#if NeedFunctionPrototypes
    XPoint*		/* points */,
    int			/* n */,
    int			/* fill_rule */
#endif
);

extern int XRectInRegion(
#if NeedFunctionPrototypes
    XRegion		/* r */,
    int			/* x */,
    int			/* y */,
    unsigned int	/* width */,
    unsigned int	/* height */
#endif
);

extern int XShrinkRegion(
#if NeedFunctionPrototypes
    XRegion		/* r */,
    int			/* dx */,
    int			/* dy */
#endif
);

extern int XSubtractRegion(
#if NeedFunctionPrototypes
    XRegion		/* sra */,
    XRegion		/* srb */,
    XRegion		/* dr_return */
#endif
);

extern int XUnionRectWithRegion(
#if NeedFunctionPrototypes
    XRectangle*		/* rectangle */,
    XRegion		/* src_region */,
    XRegion		/* dest_region_return */
#endif
);

extern int XUnionRegion(
#if NeedFunctionPrototypes
    XRegion		/* sra */,
    XRegion		/* srb */,
    XRegion		/* dr_return */
#endif
);

extern int XXorRegion(
#if NeedFunctionPrototypes
    XRegion		/* sra */,
    XRegion		/* srb */,
    XRegion		/* dr_return */
#endif
);

#ifdef __cplusplus
};
#endif

#endif /* _XUTIL_H_ */
