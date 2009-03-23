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


// VSocket.cpp

// The VSocket class provides a platform-independent socket abstraction
// with the simple functionality required for an RFB server.

class VSocket;

////////////////////////////////////////////////////////
// System includes

#include "stdhdrs.h"

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

#ifdef __WIN32__
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

////////////////////////////////////////////////////////
// Socket implementation

#include "VSocket.h"

// The socket timeout value (currently 5 seconds, for no reason...)
// *** THIS IS NOT CURRENTLY USED ANYWHERE
const VInt rfbMaxClientWait = 5000;

extern HANDLE VncTerminateEvent;

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
	
  wVersionRequested = MAKEWORD(2, 0);
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
	if (m_status)
	{
		WSACleanup();
	}
}

////////////////////////////

VSocket::VSocket()
{
  // Clear out the internal socket fields
  sock = -1;
}

VSocket::VSocket(int inSock)
{
  sock = inSock;

 // if (!mut)
//	  mut = CreateMutex(NULL, FALSE, NULL);

//  int one = 1;
//  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
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
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
      return VFalse;
    }

  // Set the socket options:
#ifndef WIN32
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)))
    {
      return VFalse;
    }
#endif
  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)))
	{
	  return VFalse;
	}

  return VTrue;
}

////////////////////////////

VBool
VSocket::Close()
{
  if (sock >= 0)
    {
	  //vnclog.Print(LL_SOCKINFO, VNCLOG("closing socket\n"));

	  shutdown(sock, SD_BOTH);
#ifdef __WIN32__
	  closesocket(sock);
#else
	  close(sock);
#endif
      sock = -1;

		SetEvent(VncTerminateEvent);
    }
  return VTrue;
}

////////////////////////////

VBool
VSocket::Shutdown()
{
  if (sock >= 0)
    {
	  //vnclog.Print(LL_SOCKINFO, VNCLOG("shutdown socket\n"));

	  shutdown(sock, SD_BOTH);
    }
  return VTrue;
}

////////////////////////////

VBool
VSocket::Bind(const VCard port, const VBool localOnly)
{
  struct sockaddr_in addr;

  // Check that the socket is open!
  if (sock < 0)
    return VFalse;

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

  return VTrue;
}

////////////////////////////

VBool
VSocket::Connect(const VString address, const VCard port)
{
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
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
    return VTrue;

  return VFalse;
}

////////////////////////////

VBool
VSocket::Listen()
{
  // Check socket
  if (sock < 0)
    return VFalse;

	// Set it to listen
  if (listen(sock, 5) < 0)
    return VFalse;

  return VTrue;
}

////////////////////////////

VSocket *
VSocket::Accept()
{
  const int one = 1;

  int new_socket_id;
  VSocket * new_socket;

  // Check this socket
  if (sock < 0)
    return NULL;

  // Accept an incoming connection
  if ((new_socket_id = accept(sock, NULL, 0)) < 0)
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
    }

  // Attempt to set the new socket's options
  setsockopt(new_socket->sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));

  return new_socket;
}

////////////////////////////

VString
VSocket::GetPeerName()
{
/*	struct sockaddr_in	sockinfo;
	struct in_addr		address;
	int					sockinfosize = sizeof(sockinfo);
	VString				name;

	// Get the peer address for the client socket
	getpeername(sock, (struct sockaddr *)&sockinfo, &sockinfosize);
	memcpy(&address, &sockinfo.sin_addr, sizeof(address));

	name = inet_ntoa(address);
	if (name == NULL)
		return "<unavailable>";
	else
		return name;
	*/

	return "<unavailable>";
}

////////////////////////////

VString
VSocket::GetSockName()
{
/*	struct sockaddr_in	sockinfo;
	struct in_addr		address;
	int					sockinfosize = sizeof(sockinfo);
	VString				name;

	// Get the peer address for the client socket
	getsockname(sock, (struct sockaddr *)&sockinfo, &sockinfosize);
	memcpy(&address, &sockinfo.sin_addr, sizeof(address));

	name = inet_ntoa(address);
	if (name == NULL)
		return "<unavailable>";
	else
		return name;
	*/

	return "<unavailable>";
}

////////////////////////////

VCard32
VSocket::Resolve(const VString address)
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
VSocket::SetTimeout(VCard32 millisecs)
{
	if (LOBYTE(winsockVersion) < 2)
		return VFalse;
	int timeout=millisecs;
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

VInt
VSocket::Send(const char *buff, const VCard bufflen)
{
	VInt res;

	sockMutex.lock();
  res = send(sock, buff, bufflen, 0);
	sockMutex.unlock();
	
  return res;
}

////////////////////////////

VBool
VSocket::SendExact(const char *buff, const VCard bufflen)
{
  return Send(buff, bufflen) == (VInt)bufflen;
}

////////////////////////////

VInt
VSocket::Read(char *buff, const VCard bufflen)
{
	VInt res;

	sockMutex.lock();
  res = recv(sock, buff, bufflen, 0);
 	sockMutex.unlock();

	return res;
}

////////////////////////////

VBool
VSocket::ReadExact(char *buff, const VCard bufflen)
{
	int n;
	VCard currlen = bufflen;

	while (currlen > 0)
	{
		// Try to read some data in
		n = Read(buff, currlen);
	
		if (n > 0)
		{
			// Adjust the buffer position and size
			buff += n;
			currlen -= n;
		} else if (n == 0) {
			//vnclog.Print(LL_SOCKERR, VNCLOG("zero bytes read\n"));

			return VFalse;
		} else {
			if (WSAGetLastError() != WSAEWOULDBLOCK)
			{
				//vnclog.Print(LL_SOCKERR, VNCLOG("socket error %d\n"), WSAGetLastError());
				return VFalse;
			}
		}
    }

	return VTrue;
}



