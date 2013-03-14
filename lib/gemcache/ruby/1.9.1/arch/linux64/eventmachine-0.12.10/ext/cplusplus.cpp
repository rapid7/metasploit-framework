/*****************************************************************************

$Id$

File:     cplusplus.cpp
Date:     27Jul07

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#include "project.h"


namespace EM {
	static map<unsigned long, Eventable*> Eventables;
	static map<unsigned long, void(*)()> Timers;
}


/*******
EM::Run
*******/

void EM::Run (void (*start_func)())
{
	evma_set_epoll (1);
	evma_initialize_library (EM::Callback);
	if (start_func)
		AddTimer (0, start_func);
	evma_run_machine();
	evma_release_library();
}

/************
EM::AddTimer
************/

void EM::AddTimer (int milliseconds, void (*func)())
{
	if (func) {
		const unsigned long sig = evma_install_oneshot_timer (milliseconds);
		#ifndef HAVE_MAKE_PAIR
		Timers.insert (map<unsigned long, void(*)()>::value_type (sig, func));
		#else
		Timers.insert (make_pair (sig, func));
		#endif
	}
}


/***************
EM::StopReactor
***************/

void EM::StopReactor()
{
	evma_stop_machine();
}


/********************
EM::Acceptor::Accept
********************/

void EM::Acceptor::Accept (const unsigned long signature)
{
	Connection *c = MakeConnection();
	c->Signature = signature;
	#ifndef HAVE_MAKE_PAIR
	Eventables.insert (std::map<unsigned long,EM::Eventable*>::value_type (c->Signature, c));
	#else
	Eventables.insert (make_pair (c->Signature, c));
	#endif
	c->PostInit();
}

/************************
EM::Connection::SendData
************************/

void EM::Connection::SendData (const char *data)
{
	if (data)
		SendData (data, strlen (data));
}


/************************
EM::Connection::SendData
************************/

void EM::Connection::SendData (const char *data, int length)
{
	evma_send_data_to_connection (Signature, data, length);
}


/*********************
EM::Connection::Close
*********************/

void EM::Connection::Close (bool afterWriting)
{
	evma_close_connection (Signature, afterWriting);
}


/***************************
EM::Connection::BindConnect
***************************/

void EM::Connection::BindConnect (const char *bind_addr, int bind_port, const char *host, int port)
{
	Signature = evma_connect_to_server (bind_addr, bind_port, host, port);
	#ifndef HAVE_MAKE_PAIR
	Eventables.insert (std::map<unsigned long,EM::Eventable*>::value_type (Signature, this));
	#else
	Eventables.insert (make_pair (Signature, this));
	#endif
}

/***********************
EM::Connection::Connect
***********************/

void EM::Connection::Connect (const char *host, int port)
{
	this->BindConnect(NULL, 0, host, port);
}

/*******************
EM::Acceptor::Start
*******************/

void EM::Acceptor::Start (const char *host, int port)
{
	Signature = evma_create_tcp_server (host, port);
	#ifndef HAVE_MAKE_PAIR
	Eventables.insert (std::map<unsigned long,EM::Eventable*>::value_type (Signature, this));
	#else
	Eventables.insert (make_pair (Signature, this));
	#endif
}



/************
EM::Callback
************/

void EM::Callback (const unsigned long sig, int ev, const char *data, const unsigned long length)
{
	EM::Eventable *e;
	void (*f)();

	switch (ev) {
		case EM_TIMER_FIRED:
			f = Timers [length]; // actually a binding
			if (f)
				(*f)();
			Timers.erase (length);
			break;

		case EM_CONNECTION_READ:
			e = EM::Eventables [sig];
			e->ReceiveData (data, length);
			break;

		case EM_CONNECTION_COMPLETED:
			e = EM::Eventables [sig];
			e->ConnectionCompleted();
			break;

		case EM_CONNECTION_ACCEPTED:
			e = EM::Eventables [sig];
			e->Accept (length); // actually a binding
			break;

		case EM_CONNECTION_UNBOUND:
			e = EM::Eventables [sig];
			e->Unbind();
			EM::Eventables.erase (sig);
			delete e;
			break;

		case EM_SSL_HANDSHAKE_COMPLETED:
			e = EM::Eventables [sig];
			e->SslHandshakeCompleted();
			break;
	}
}

