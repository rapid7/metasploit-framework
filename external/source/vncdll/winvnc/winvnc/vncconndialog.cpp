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


// vncConnDialog.cpp: implementation of the vncConnDialog class, used
// to forge outgoing connections to VNC-viewer 

#include "stdhdrs.h"
#include "vncConnDialog.h"
#include "WinVNC.h"

#include "resource.h"

// Constructor

vncConnDialog::vncConnDialog(vncServer *server)
{
	m_server = server;
}

// Destructor

vncConnDialog::~vncConnDialog()
{
}

// Routine called to activate the dialog and, once it's done, delete it

void vncConnDialog::DoDialog()
{
	DialogBoxParam(hAppInstance, MAKEINTRESOURCE(IDD_OUTGOING_CONN), 
		NULL, (DLGPROC) vncConnDlgProc, (LONG) this);
	delete this;
}

// Callback function - handles messages sent to the dialog box

BOOL CALLBACK vncConnDialog::vncConnDlgProc(HWND hwnd,
											UINT uMsg,
											WPARAM wParam,
											LPARAM lParam) {
	// This is a static method, so we don't know which instantiation we're 
	// dealing with. But we can get a pseudo-this from the parameter to 
	// WM_INITDIALOG, which we therafter store with the window and retrieve
	// as follows:
	vncConnDialog *_this = (vncConnDialog *) GetWindowLong(hwnd, GWL_USERDATA);

	switch (uMsg) {

		// Dialog has just been created
	case WM_INITDIALOG:
		{
			// Save the lParam into our user data so that subsequent calls have
			// access to the parent C++ object

      SetWindowLong(hwnd, GWL_USERDATA, lParam);
      vncConnDialog *_this = (vncConnDialog *) lParam;
          
      // Make the text entry box active
      SetFocus(GetDlgItem(hwnd, IDC_HOSTNAME_EDIT));

      // Return success!
			return TRUE;
		}

		// Dialog has just received a command
	case WM_COMMAND:
		switch (LOWORD(wParam)) {

			// User clicked OK or pressed return
		case IDOK:
      {
        char viewer[256];
			  char hostname[256];
        VCard display_or_port;

			  // Get the viewer to connect to
			  GetDlgItemText(hwnd, IDC_HOSTNAME_EDIT, viewer, 256);

        // Process the supplied viewer address
        int result = sscanf(viewer, "%255[^:]:%u", hostname, &display_or_port);
        if (result == 1) {
          display_or_port = 0;
          result = 2;
        }
        if (result == 2) {
          // Correct a display number to a port number if required
          if (display_or_port < 100) {
            display_or_port += INCOMING_PORT_OFFSET;
          }

			    // Attempt to create a new socket
			    VSocket *tmpsock;
			    tmpsock = new VSocket;
			    if (!tmpsock)
				    return TRUE;

			    // Connect out to the specified host on the VNCviewer listen port
			    // To be really good, we should allow a display number here but
			    // for now we'll just assume we're connecting to display zero
			    tmpsock->Create();
			    if (tmpsock->Connect(hostname, display_or_port)) {
				    // Add the new client to this server
				    _this->m_server->AddClient(tmpsock, TRUE, TRUE);

				    // And close the dialog
            EndDialog(hwnd, TRUE);
			    } else {
				    // Print up an error message
				    MessageBox(NULL, 
                        "Failed to connect to listening VNC viewer",
                        "Outgoing Connection",
					    MB_OK | MB_ICONEXCLAMATION );
				    delete tmpsock;
			    }
        } else {
          // We couldn't process the machine specification
          MessageBox(NULL, "Unable to process specified hostname and display/port",
            "Outgoing Connection", MB_OK | MB_ICONEXCLAMATION);
        }
      }
			return TRUE;

			// Cancel the dialog
		case IDCANCEL:
			EndDialog(hwnd, FALSE);
			return TRUE;
		};

		break;

	case WM_DESTROY:
		EndDialog(hwnd, FALSE);
		return TRUE;
	}
	return 0;
}

