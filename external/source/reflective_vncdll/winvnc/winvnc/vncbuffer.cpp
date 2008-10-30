//  Copyright (C) 2002-2003 RealVNC Ltd. All Rights Reserved.
//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//
//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.


// ScrBuffer implementation

#include "stdhdrs.h"

// Header

#include "vncDesktop.h"
#include "rfbMisc.h"

#include "vncBuffer.h"

// Implementation

vncBuffer::vncBuffer()
{
	m_freemainbuff = FALSE;
	m_mainbuff = NULL;
	m_backbuff = NULL;
	m_backbuffsize = 0;
	m_desktop=NULL;
}

vncBuffer::~vncBuffer()
{
	if (m_freemainbuff) {
		// We need to free the slow-blit buffer
		if (m_mainbuff != NULL)
		{
			delete [] m_mainbuff;
			m_mainbuff = NULL;
		}
	}
	if (m_backbuff != NULL)
	{
		delete [] m_backbuff;
		m_backbuff = NULL;
	}
	m_backbuffsize = 0;
}

void
vncBuffer::SetDesktop(vncDesktop *desktop)
{
	m_desktop=desktop;
	CheckBuffer();
}

rfb::Rect
vncBuffer::GetSize()
{
	return rfb::Rect(0, 0, m_scrinfo.framebufferWidth, m_scrinfo.framebufferHeight);
}

rfbPixelFormat
vncBuffer::GetLocalFormat()
{
	return m_scrinfo.format;
}

BOOL
vncBuffer::CheckBuffer()
{
	// Get the screen format, in case it has changed
	m_desktop->FillDisplayInfo(&m_scrinfo);
	m_bytesPerRow = m_scrinfo.framebufferWidth * m_scrinfo.format.bitsPerPixel/8;

	// Check that the local format buffers are sufficient
	if ((m_backbuffsize != m_desktop->ScreenBuffSize()) || !m_freemainbuff)
	{
		//vnclog.Print(LL_INTINFO, VNCLOG("request local buffer[%d]\n"), m_desktop->ScreenBuffSize());
		if (m_freemainbuff) {
			// Slow blits were enabled - free the slow blit buffer
			if (m_mainbuff != NULL)
			{
				delete [] m_mainbuff;
				m_mainbuff = NULL;
			}
		}

		if (m_backbuff != NULL)
		{
			delete [] m_backbuff;
			m_backbuff = NULL;
		}
		m_backbuffsize = 0;

		// Check whether or not the vncDesktop is using fast blits
		m_mainbuff = (BYTE *)m_desktop->OptimisedBlitBuffer();
		if (m_mainbuff) {
			// Prevent us from freeing the DIBsection buffer
			m_freemainbuff = FALSE;
			//vnclog.Print(LL_INTINFO, VNCLOG("fast blits detected - using DIBsection buffer\n"));
		} else {
			// Create our own buffer to copy blits through
			m_freemainbuff = TRUE;
			if ((m_mainbuff = new BYTE [m_desktop->ScreenBuffSize()]) == NULL)
			{
				//vnclog.Print(LL_INTERR, VNCLOG("unable to allocate main buffer[%d]\n"), m_desktop->ScreenBuffSize());
				return FALSE;
			}
			memset(m_mainbuff, 0, m_desktop->ScreenBuffSize());
		}

		// Always create a back buffer
		if ((m_backbuff = new BYTE [m_desktop->ScreenBuffSize()]) == NULL)
		{
			//vnclog.Print(LL_INTERR, VNCLOG("unable to allocate back buffer[%d]\n"), m_desktop->ScreenBuffSize());
			return FALSE;
		}
		memset(m_backbuff, 0, m_desktop->ScreenBuffSize());
		m_backbuffsize = m_desktop->ScreenBuffSize();
		
		// Clear the backbuffer
		//memcpy(m_backbuff, m_mainbuff, m_desktop->ScreenBuffSize());
	}

	//vnclog.Print(LL_INTINFO, VNCLOG("local buffer=%d\n"), m_backbuffsize);

	return TRUE;
}

// Check a specified rectangle for changes and fill the region with
// the changed subrects
#pragma function(memcpy,memcmp)
void
vncBuffer::CheckRect(rfb::Region2D &dest, const rfb::Rect &srcrect)
{
	if (!FastCheckMainbuffer())
		return;

	const int BLOCK_SIZE = 32;
	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;

	rfb::Rect new_rect;
	rfb::Rect srect = srcrect;

	int x, y, ay, by;

	// DWORD align the incoming rectangle.  (bPP will be 8, 16 or 32)
	if (bytesPerPixel < 4) {
		if (bytesPerPixel == 1)				// 1 byte per pixel
			srect.tl.x -= (srect.tl.x & 3);	// round down to nearest multiple of 4
		else								// 2 bytes per pixel
			srect.tl.x -= (srect.tl.x & 1);	// round down to nearest multiple of 2
	}

	// Scan down the rectangle
	unsigned char *o_topleft_ptr = m_backbuff + (srect.tl.y * m_bytesPerRow) + (srect.tl.x * bytesPerPixel);
	unsigned char *n_topleft_ptr = m_mainbuff + (srect.tl.y * m_bytesPerRow) + (srect.tl.x * bytesPerPixel);
	for (y = srect.tl.y; y<srect.br.y; y+=BLOCK_SIZE)
	{
		// Work out way down the bitmap
		unsigned char * o_row_ptr = o_topleft_ptr;
		unsigned char * n_row_ptr = n_topleft_ptr;

		const UINT blockbottom = min(y+BLOCK_SIZE, srect.br.y);
		for (x = srect.tl.x; x<srect.br.x; x+=BLOCK_SIZE)
		{
			// Work our way across the row
			unsigned char *n_block_ptr = n_row_ptr;
			unsigned char *o_block_ptr = o_row_ptr;

			const UINT blockright = min(x+BLOCK_SIZE, srect.br.x);
			const UINT bytesPerBlockRow = (blockright-x) * bytesPerPixel;

			// Scan this block
			for (ay = y; ay < blockbottom; ay++)
			{
				if (memcmp(n_block_ptr, o_block_ptr, bytesPerBlockRow) != 0)
				{
					// A pixel has changed, so this block needs updating
					new_rect.tl.y = y;
					new_rect.tl.x = x;
					new_rect.br.x = blockright;
					new_rect.br.y = blockbottom;
					dest = dest.union_(rfb::Region2D(new_rect));

					// Copy the changes to the back buffer
					for (by = ay; by < blockbottom; by++)
					{
						memcpy(o_block_ptr, n_block_ptr, bytesPerBlockRow);
						n_block_ptr+=m_bytesPerRow;
						o_block_ptr+=m_bytesPerRow;
					}

					break;
				}

				n_block_ptr += m_bytesPerRow;
				o_block_ptr += m_bytesPerRow;
			}

			o_row_ptr += bytesPerBlockRow;
			n_row_ptr += bytesPerBlockRow;
		}

		o_topleft_ptr += m_bytesPerRow * BLOCK_SIZE;
		n_topleft_ptr += m_bytesPerRow * BLOCK_SIZE;
	}
}

void
vncBuffer::GrabRegion(const rfb::Region2D &src)
{
	rfb::RectVector rects;
	rfb::RectVector::iterator i;
	rfb::Rect grabRect;

	//
	// - Are there any rectangles to check?
	//
	src.get_rects(rects, 1, 1);
	if (rects.empty()) return;

	//
	// - Grab the rectangles that may have changed
	//

	// The rectangles should have arrived in order of height
	for (i = rects.begin(); i != rects.end(); i++)
	{
		rfb::Rect current = *i;

		// Check that this rectangle is part of this capture region
		if (current.tl.y > grabRect.br.y)
		{
			// If the existing rect is non-null the capture it
			if (!grabRect.is_empty()) GrabRect(grabRect);

			grabRect = current;
		} else {
			grabRect = current.union_boundary(grabRect);
		}
	}

	// If there are still some rects to be done then do them
	if (!grabRect.is_empty()) GrabRect(grabRect);
}

void
vncBuffer::CheckRegion(rfb::Region2D &dest, const rfb::Region2D &src)
{
	rfb::RectVector rects;
	rfb::RectVector::iterator i;

	// If there is nothing to do then do nothing...
	src.get_rects(rects, 1, 1);
	if (rects.empty()) return;

	//
	// - Scan the specified rectangles for changes
	//

	for (i = rects.begin(); i != rects.end(); i++)
	{
		// Get the buffer to check for changes in the rect
		CheckRect(dest, *i);
	}
}

void
vncBuffer::GrabRect(const rfb::Rect &rect)
{
	if (!FastCheckMainbuffer()) return;
	m_desktop->CaptureScreen(rect, m_mainbuff, m_backbuffsize);
}

void
vncBuffer::CopyRect(const rfb::Rect &dest, const rfb::Point &delta)
{
	rfb::Rect src = dest.translate(delta.negate());

	// Copy the data from one part of the back-buffer to another!
	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel/8;
	const UINT bytesPerLine = (dest.br.x-dest.tl.x)*bytesPerPixel;
	BYTE *srcptr = m_backbuff + (src.tl.y * m_bytesPerRow) +
		(src.tl.x * bytesPerPixel);
	BYTE *destptr = m_backbuff + (dest.tl.y * m_bytesPerRow) +
		(dest.tl.x * bytesPerPixel);

	// Copy the data around in the right order
	if (dest.tl.y < src.tl.y)
	{
		for (int y=dest.tl.y; y < dest.br.y; y++)
		{
			memmove(destptr, srcptr, bytesPerLine);
			srcptr+=m_bytesPerRow;
			destptr+=m_bytesPerRow;
		}
	}
	else
	{
		srcptr += (m_bytesPerRow * ((dest.br.y-dest.tl.y)-1));
		destptr += (m_bytesPerRow * ((dest.br.y-dest.tl.y)-1));
		for (int y=dest.br.y; y > dest.tl.y; y--)
		{
			memmove(destptr, srcptr, bytesPerLine);
			srcptr-=m_bytesPerRow;
			destptr-=m_bytesPerRow;
		}
	}
}

void
vncBuffer::GrabMouse()
{
	if (!FastCheckMainbuffer()) return;
	m_desktop->CaptureMouse(m_mainbuff, m_backbuffsize);
}

void
vncBuffer::GetMousePos(rfb::Rect &rect)
{
	rect = m_desktop->MouseRect();
}

void
vncBuffer::Clear(const rfb::Rect &rect)
{
	if (!FastCheckMainbuffer())
		return;

	//vnclog.Print(LL_INTINFO,
	//	VNCLOG("clearing rectangle (%d, %d)-(%d, %d)\n"),
	//	rect.tl.x, rect.tl.y, rect.br.x, rect.br.y);

	// Update the contents of a region, to stop it from being marked as having changed
	BYTE *backptr = m_backbuff + (rect.tl.y * m_bytesPerRow) + (rect.tl.x * m_scrinfo.format.bitsPerPixel/8);
	BYTE *mainptr = m_mainbuff + (rect.tl.y * m_bytesPerRow) + (rect.tl.x * m_scrinfo.format.bitsPerPixel/8);
	const UINT bytesPerLine = (rect.br.x-rect.tl.x)*(m_scrinfo.format.bitsPerPixel/8);
	for (int y=rect.tl.y; y < rect.br.y; y++)
	{
		memcpy(backptr, mainptr, bytesPerLine);
		backptr+=m_bytesPerRow;
		mainptr+=m_bytesPerRow;
	}
}

// Verify that the fast blit buffer hasn't changed
inline BOOL
vncBuffer::FastCheckMainbuffer() {
	VOID *tmp = m_desktop->OptimisedBlitBuffer();
	if (tmp && (m_mainbuff != tmp))
		return CheckBuffer();
	return TRUE;
}
