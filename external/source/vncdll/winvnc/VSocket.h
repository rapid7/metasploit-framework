//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//  Copyright (C) 2001 HorizonLive.com, Inc. All Rights Reserved.
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
// TightVNC distribution homepage on the Web: http://www.tightvnc.com/
//
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.


// VSocket.h

// RFB V3.0

// The VSocket class provides simple socket functionality,
// independent of platform.  Hurrah.

class VSocket;

#if (!defined(_ATT_VSOCKET_DEFINED))
#define _ATT_VSOCKET_DEFINED

#include <omnithread.h>
#include "VTypes.h"

// This class is used as a part of output queue
class AIOBlock
{
public:
	size_t data_size;		// Data size in this block
	char *data_ptr;			// Beginning of the data buffer
	AIOBlock *next;			// Next block or NULL for the last block

	AIOBlock(int size, const char *data = NULL) {
		next = NULL;
		data_size = size;
		data_ptr = new char[size];
		if (data_ptr && data)
			memcpy(data_ptr, data, size);
	}
	~AIOBlock() {
		if (data_ptr)
			delete[] data_ptr;
	}
};

////////////////////////////
// Socket implementation

// Create one or more VSocketSystem objects per application
class VSocketSystem
{
public:
	VSocketSystem();
	~VSocketSystem();
	VBool Initialised() {return m_status;};
private:
	VBool m_status;
};

// The main socket class
class VSocket
{
public:
  // Constructor/Destructor
  VSocket();
  VSocket( WSAPROTOCOL_INFO * pSocketInfo, HANDLE hClose );
  virtual ~VSocket();

  ////////////////////////////
  // Socket implementation

  // Create
  //        Create a socket and attach it to this VSocket object
  VBool Create();

  // Shutdown
  //        Shutdown the currently attached socket
  VBool Shutdown();

  // Close
  //        Close the currently attached socket
  VBool Close();

  // Bind
  //        Bind the attached socket to the specified port
  //		If localOnly is VTrue then the socket is bound only
  //        to the loopback adapter. If checkIfInUse is VTrue,
  //        then the socket won't be bound to an address which
  //        is already in use (i.e. accepts connections).
  VBool Bind(const VCard port, const VBool localOnly = VFalse,
			 const VBool checkIfInUse = VFalse);

  // Connect
  //        Make a stream socket connection to the specified port
  //        on the named machine.
  VBool Connect(VStringConst address, const VCard port);

  // Listen
  //        Set the attached socket to listen for connections
  VBool Listen();

  // Accept
  //        If the attached socket is set to listen then this
  //        call blocks waiting for an incoming connection, then
  //        returns a new socket object for the new connection
  VSocket *Accept();

  // TryAccept
  //        Non-blocking version of Accept. It waits for an
  //        incoming connection only for the specified number of
  //        milliseconds. It returns VFalse on error, otherwise stores
  //        either pointer to the new VSocket, or NULL on timeout
  VBool TryAccept(VSocket **new_socket, long ms);

  // GetPeerName
  //        If the socket is connected then this returns the name
  //        of the machine to which it is connected.
  //        This string MUST be copied before the next socket call...
  VString GetPeerName();

  // GetSockName
  //		If the socket exists then the name of the local machine
  //		is returned.  This string MUST be copied before the next
  //		socket call!
  VString GetSockName();

  // Resolve
  //        Uses the Winsock API to resolve the supplied DNS name to
  //        an IP address and returns it as an Int32
  static VCard32 Resolve(VStringConst name);

  // SetTimeout
  //        Sets the socket timeout on reads and writes.
  VBool SetTimeout(VCard32 secs);

  // I/O routines

  // Send and Read return the number of bytes sent or recieved.
  VInt Send(const char *buff, const VCard bufflen);
  VInt Read(char *buff, const VCard bufflen);

  // SendExact and ReadExact attempt to send and recieve exactly
  // the specified number of bytes.
  VBool SendExact(const char *buff, const VCard bufflen);
  VBool ReadExact(char *buff, const VCard bufflen);

  // SendQueued sends as much data as possible immediately,
  // and puts remaining bytes in a queue, to be sent later.
  VBool SendQueued(const char *buff, const VCard bufflen);

  ////////////////////////////
  // Internal structures
protected:
  // The internal socket id
  int sock;
  HANDLE hCloseEvent;

  // Output queue
  size_t bytes_sent;
  AIOBlock *out_queue;
  omni_mutex queue_lock;

  VBool SendFromQueue();
};

#endif // _ATT_VSOCKET_DEFINED
