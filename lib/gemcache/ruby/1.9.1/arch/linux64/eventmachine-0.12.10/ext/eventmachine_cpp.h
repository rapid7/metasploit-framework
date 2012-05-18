/*****************************************************************************

$Id$

File:     eventmachine_cpp.h
Date:     27Jul07

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#ifndef __EVMA_EventmachineCpp__H_
#define __EVMA_EventmachineCpp__H_


// This material is only for directly integrating EM into C++ programs.

namespace EM {

	void Callback (const unsigned long sig, int event, const char *data, const unsigned long length);
	void Run (void(*)(void));
	void AddTimer (int, void(*)());
	void StopReactor();

	/***************
	class Eventable
	***************/

	class Eventable {
		public:
			Eventable() {}
			virtual ~Eventable() {}

			unsigned long Signature;

			// Called by the framework
			virtual void ReceiveData (const char *data, int length) {}
			virtual void ConnectionCompleted() {}
			virtual void Accept (const unsigned long) {}
			virtual void Unbind() {}
			virtual void PostInit() {}
			virtual void SslHandshakeCompleted() {}

			void StopReactor() {EM::StopReactor();}
	};

	/****************
	class Connection
	****************/

	class Connection: public Eventable {
		public:
			Connection() {}
			virtual ~Connection() {}

			virtual void Connect (const char*, int);
			virtual void BindConnect (const char *, int, const char*, int);

			void SendData (const char *data);
			void SendData (const char *data, int length);
			void Close (bool afterWriting);
	};


	/**************
	class Acceptor
	**************/

	class Acceptor: public Eventable {
		public:
			Acceptor() {PostInit();}
			virtual ~Acceptor() {}

			void Start (const char*, int);
			void Accept (const unsigned long);

			virtual Connection *MakeConnection() {return new Connection();}
	};


};





#endif // __EVMA_EventmachineCpp__H_
