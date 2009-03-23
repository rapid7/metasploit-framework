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

// vncTimedMsgBox

// vncTimedMsgBox::Do spawns an omni-thread to draw the message
// box and wait a few seconds before returning, leaving the message-box displayed
// until WinVNC quits.

#include "stdhdrs.h"
#include "omnithread.h"

#include "vncTimedMsgBox.h"

// The message-box delay
const UINT TIMED_MSGBOX_DELAY = 4000;

// The vncTimedMsgBoxThread class

class vncTimedMsgBoxThread : public omni_thread
{
public:
	vncTimedMsgBoxThread(const char *caption, const char *title, UINT type)
	{
		m_type = type;
		m_caption = strdup(caption);
		m_title = strdup(title);
	};
	virtual ~vncTimedMsgBoxThread()
	{
		if (m_caption != NULL)
			free(m_caption);
		if (m_title != NULL)
			free(m_title);
	};
	virtual void run(void *)
	{
		// Create the desired dialog box
		if (m_caption == NULL)
			return;
		MessageBox(NULL, m_caption, m_title, m_type | MB_OK);
	};
	char *m_caption;
	char *m_title;
	UINT m_type;
};

// The main vncTimedMsgBox class

void
vncTimedMsgBox::Do(const char *caption, const char *title, UINT type)
{
	// Create the thread object
	vncTimedMsgBoxThread *thread = new vncTimedMsgBoxThread(caption, title, type);
	if (thread == NULL)
		return;

	// Start the thread object
	thread->start();

	// And wait a few seconds
	Sleep(TIMED_MSGBOX_DELAY);
}