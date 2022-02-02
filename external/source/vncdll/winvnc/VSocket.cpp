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


// VSocket.cpp

// The VSocket class provides a platform-independent socket abstraction
// with the simple functionality required for an RFB server.

class VSocket;

////////////////////////////////////////////////////////
// System includes

#include "stdhdrs.h"

// Visual C++ .NET 2003 compatibility
#if (_MSC_VER>= 1300)
#include <iostream>
#else
#include <iostream.h>
#endif

#include <stdio.h>
#ifdef __WIN32__
#include <io.h>
#include <winsock.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#endif
#include <sys/types.h>

////////////////////////////////////////////////////////
// Custom includes

#include "VTypes.h"

////////////////////////////////////////////////////////
// *** Lovely hacks to make Win32 work.  Hurrah!

#if defined(__WIN32__) && !defined(EWOULDBLOCK)
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

////////////////////////////////////////////////////////
// Socket implementation

#include "VSocket.h"

// The socket timeout value (currently 5 seconds, for no reason...)
// *** THIS IS NOT CURRENTLY USED ANYWHERE
const VInt rfbMaxClientWait = 5000;

////////////////////////////
// Socket implementation initialisation

static WORD winsockVersion = 0;

VSocketSystem::VSocketSystem()
{
  // Initialise the socket subsystem
  // This is only provided for compatibility with Windows.

#ifdef __WIN32__
  // Initialise WinPoxySockets on Win32
  WORD wVersionRequested;
  WSADATA wsaData;
	
  wVersionRequested = MAKEWORD(2, 2);
  if (WSAStartup(wVersionRequested, &wsaData) != 0)
  {
    m_status = VFalse;
	return;
  }

  winsockVersion = wsaData.wVersion;
 
#else
  // Disable the nasty read/write failure signals on UNIX
  signal(SIGPIPE, SIG_IGN);
#endif

  // If successful, or if not required, then continue!
  m_status = VTrue;
}

VSocketSystem::~VSocketSystem()
{
	/*if (m_status)
	{
		WSACleanup();
	}*/
}

////////////////////////////

VSocket::VSocket()
{
  // Clear out the internal socket fields
  sock = -1;
  hCloseEvent = NULL;
  out_queue = NULL;
}

VSocket::VSocket( WSAPROTOCOL_INFO * pSocketInfo, HANDLE hClose )
{
	sock = (int)WSASocket( AF_INET, SOCK_STREAM, 0, pSocketInfo, 0, 0 );
	if( sock == INVALID_SOCKET )
		sock = -1;
	//BREAK_ON_WSAERROR( "[VNCDLL] vncdll_run. WSASocketA failed" );

  // Clear out the internal socket fields
  //sock = (int)socket;
  hCloseEvent = hClose;
  out_queue = NULL;
}
////////////////////////////

VSocket::~VSocket()
{
  // Close the socket
  Close();
}

////////////////////////////

VBool
VSocket::Create()
{
  const int one = 1;

  // Check that the old socket was closed
  if (sock >= 0)
    Close();

  // Create the socket
  if ((sock = (int)socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
      return VFalse;
    }

  // Set the socket options:
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)))
    {
      return VFalse;
    }
  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)))
	{
	  return VFalse;
	}

  return VTrue;
}

////////////////////////////

extern HANDLE hCloseEvent;

VBool VSocket::Close()
{
  if( sock >= 0 )
  {
	//shutdown(sock, SD_BOTH);
	//closesocket(sock);
	//CloseHandle( (HANDLE)sock );
	sock = -1;
	SetEvent( hCloseEvent );
  }

  while (out_queue)
	{
	  AIOBlock *next = out_queue->next;
	  delete out_queue;
	  out_queue = next;
	}

  return VTrue;
}

////////////////////////////

VBool
VSocket::Shutdown()
{
  /*if (sock >= 0)
    {
	  shutdown(sock, SD_BOTH);
    }*/
  while (out_queue)
	{
	  AIOBlock *next = out_queue->next;
	  delete out_queue;
	  out_queue = next;
	}

  return VTrue;
}

////////////////////////////

VBool
VSocket::Bind(const VCard port, const VBool localOnly,
			  const VBool checkIfInUse)
{
  return VFalse;
  /*struct sockaddr_in addr;

  // Check that the socket is open!
  if (sock < 0)
    return VFalse;

  // If a specific port is being set then check it's not already used!
  if (port != 0 && checkIfInUse)
  {
	VSocket dummy;

	if (dummy.Create())
	{
		// If we're able to connect then the port number is in use...
		if (dummy.Connect("localhost", port))
			return VFalse;
	}
  }

  // Set up the address to bind the socket to
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (localOnly)
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  else
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

  // And do the binding
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
      return VFalse;

  return VTrue;*/
}

////////////////////////////

VBool
VSocket::Connect(VStringConst address, const VCard port)
{
  return VFalse;
  /*
  // Check the socket
  if (sock < 0)
    return VFalse;

  // Create an address structure and clear it
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));

  // Fill in the address if possible
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(address);

  // Was the string a valid IP address?
  if (addr.sin_addr.s_addr == -1)
    {
      // No, so get the actual IP address of the host name specified
      struct hostent *pHost;
      pHost = gethostbyname(address);
      if (pHost != NULL)
	  {
		  if (pHost->h_addr == NULL)
			  return VFalse;
		  addr.sin_addr.s_addr = ((struct in_addr *)pHost->h_addr)->s_addr;
	  }
	  else
	    return VFalse;
    }

  // Set the port number in the correct format
  addr.sin_port = htons(port);

  // Actually connect the socket
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    return VFalse;

  // Put the socket into non-blocking mode
#ifdef __WIN32__
  u_long arg = 1;
  if (ioctlsocket(sock, FIONBIO, &arg) != 0)
	return VFalse;
#else
  if (fcntl(sock, F_SETFL, O_NDELAY) != 0)
	return VFalse;
#endif

  return VTrue;*/
}

////////////////////////////

VBool
VSocket::Listen()
{
  return VFalse;
  /*
  // Check socket
  if (sock < 0)
    return VFalse;

	// Set it to listen
  if (listen(sock, 5) < 0)
    return VFalse;

  return VTrue;*/
}

////////////////////////////

VSocket *
VSocket::Accept()
{
  return VFalse;
  /*
  const int one = 1;

  int new_socket_id;
  VSocket * new_socket;

  // Check this socket
  if (sock < 0)
    return NULL;

  // Accept an incoming connection
  if ((new_socket_id = (int)accept(sock, NULL, 0)) < 0)
    return NULL;

  // Create a new VSocket and return it
  new_socket = new VSocket;
  if (new_socket != NULL)
    {
      new_socket->sock = new_socket_id;
    }
  else
    {
	  shutdown(new_socket_id, SD_BOTH);
	  closesocket(new_socket_id);
	  return NULL;
    }

  // Attempt to set the new socket's options
  setsockopt(new_socket->sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));

  // Put the socket into non-blocking mode
#ifdef __WIN32__
  u_long arg = 1;
  if (ioctlsocket(new_socket->sock, FIONBIO, &arg) != 0) {
	delete new_socket;
	new_socket = NULL;
  }
#else
  if (fcntl(new_socket->sock, F_SETFL, O_NDELAY) != 0) {
	delete new_socket;
	new_socket = NULL;
  }
#endif

  return new_socket;*/
}

////////////////////////////

VBool
VSocket::TryAccept(VSocket **new_socket, long ms)
{
  return VFalse;
  /*
	// Check this socket
	if (sock < 0)
		return NULL;

	struct fd_set fds;
	struct timeval tm;
	FD_ZERO(&fds);
	FD_SET((unsigned int)sock, &fds);
	tm.tv_sec = ms / 1000;
	tm.tv_usec = (ms % 1000) * 1000;
	int ready = select(sock + 1, &fds, NULL, NULL, &tm);
	if (ready == 0) {
		// Timeout
		*new_socket = NULL;
		return VTrue;
	} else if (ready != 1) {
		// Error
		return VFalse;
	}
	// Ready to accept new connection
	VSocket *s = Accept();
	if (s == NULL)
		return VFalse;
	// Success
	*new_socket = s;
	return VTrue;*/
}

////////////////////////////

VString VSocket::GetPeerName()
{
	return "<unavailable>";
}

////////////////////////////

VString VSocket::GetSockName()
{
	return "<unavailable>";
}

////////////////////////////

VCard32
VSocket::Resolve(VStringConst address)
{
  VCard32 addr;

  // Try converting the address as IP
  addr = inet_addr(address);

  // Was it a valid IP address?
  if (addr == 0xffffffff)
    {
      // No, so get the actual IP address of the host name specified
      struct hostent *pHost;
      pHost = gethostbyname(address);
      if (pHost != NULL)
	  {
		  if (pHost->h_addr == NULL)
			  return 0;
		  addr = ((struct in_addr *)pHost->h_addr)->s_addr;
	  }
	  else
		  return 0;
    }

  // Return the resolved IP address as an integer
  return addr;
}

////////////////////////////

VBool
VSocket::SetTimeout(VCard32 secs)
{
	//if (LOBYTE(winsockVersion) < 2)
	//	return VFalse;
	int timeout=secs;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR)
	{
		return VFalse;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR)
	{
		return VFalse;
	}
	return VTrue;
}

////////////////////////////

VInt VSocket::Send(const char *buff, const VCard bufflen)
{
	errno = 0;

	VInt bytes = send(sock, buff, bufflen, 0);
	if (bytes < 0)
	{
		int wsa_error = WSAGetLastError();
#ifdef __WIN32__
		if (wsa_error == WSAEWOULDBLOCK)
			errno = EWOULDBLOCK;
#endif
	}

	return bytes;
}

////////////////////////////

VBool
VSocket::SendExact(const char *buff, const VCard bufflen)
{
	struct fd_set write_fds;
	struct timeval tm;
	int count;

	// Put the data into the queue
	SendQueued(buff, bufflen);

	while (out_queue) {
		// Wait until some data can be sent
		do {
			FD_ZERO(&write_fds);
			FD_SET((unsigned int)sock, &write_fds);
			tm.tv_sec = 1;
			tm.tv_usec = 0;
			count = select(sock + 1, NULL, &write_fds, NULL, &tm);
		} while (count == 0);
		if (count < 0 || count > 1) {
			return VFalse;
		}
		// Actually send some data
		if (FD_ISSET((unsigned int)sock, &write_fds)) {
			if (!SendFromQueue())
				return VFalse;
		}
    }

	return VTrue;
}

////////////////////////////

VBool
VSocket::SendQueued(const char *buff, const VCard bufflen)
{
	omni_mutex_lock l(queue_lock);

	// Just append new bytes to the output queue
	if (!out_queue) {
		out_queue = new AIOBlock(bufflen, buff);
		bytes_sent = 0;
	} else {
		AIOBlock *last = out_queue;
		while (last->next)
			last = last->next;
		last->next = new AIOBlock(bufflen, buff);
	}

	return VTrue;
}

////////////////////////////

VBool
VSocket::SendFromQueue()
{
	omni_mutex_lock l(queue_lock);

	// Is there something to send?
	if (!out_queue)
		return VTrue;

	// Maximum data size to send at once
	size_t portion_size = out_queue->data_size - bytes_sent;
	if (portion_size > 32768)
		portion_size = 32768;

	// Try to send some data
	int bytes = Send(out_queue->data_ptr + bytes_sent, (VCard)portion_size);
	if (bytes > 0) {
		bytes_sent += bytes;
	} else if (bytes < 0 && errno != EWOULDBLOCK) {
		return VFalse;
	}

	// Remove block if all its data has been sent
	if (bytes_sent == out_queue->data_size) {
		AIOBlock *sent = out_queue;
		out_queue = sent->next;
		bytes_sent = 0;
		delete sent;
	}

	return VTrue;
}

////////////////////////////

VInt
VSocket::Read(char *buff, const VCard bufflen)
{
	errno = 0;

	VInt bytes = recv(sock, buff, bufflen, 0);

#ifdef __WIN32__
	if (bytes < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
		errno = EWOULDBLOCK;
#endif

	return bytes;
}

////////////////////////////

VBool
VSocket::ReadExact(char *buff, const VCard bufflen)
{
	int bytes;
	VCard currlen = bufflen;
	struct fd_set read_fds, write_fds;
	struct timeval tm;
	int count;

	while (currlen > 0) {
		// Wait until some data can be read or sent
		do {
			FD_ZERO(&read_fds);
			FD_SET((unsigned int)sock, &read_fds);
			FD_ZERO(&write_fds);
			if (out_queue)
				FD_SET((unsigned int)sock, &write_fds);
			tm.tv_sec = 0;
			tm.tv_usec = 50;
			count = select(sock + 1, &read_fds, &write_fds, NULL, &tm);
		} while (count == 0);
		if (count < 0 || count > 2) {
			return VFalse;
		}
		if (FD_ISSET((unsigned int)sock, &write_fds)) {
			// Try to send some data
			if (!SendFromQueue())
				return VFalse;
		}
		if (FD_ISSET((unsigned int)sock, &read_fds)) {
			// Try to read some data in
			bytes = Read(buff, currlen);
			if (bytes > 0) {
				// Adjust the buffer position and size
				buff += bytes;
				currlen -= bytes;
			} else if (bytes < 0 && errno != EWOULDBLOCK) {
				return VFalse;
			} else if (bytes == 0) {
				return VFalse;
			}
		}
    }

	return VTrue;
}

