/*****************************************************************************

$Id$

File:			cmain.cpp
Date:			06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"

/* 21Sep09: ruby 1.9 defines macros for common i/o functions that point to rb_w32_* implementations.
   We need to undef the stat to fix a build failure in evma_send_file_data_to_connection.
   See http://groups.google.com/group/eventmachine/browse_thread/thread/fc60d9bb738ffc71
*/
#if defined(BUILD_FOR_RUBY) && defined(OS_WIN32)
#undef stat
#undef fstat
#endif

static EventMachine_t *EventMachine;
static int bUseEpoll = 0;
static int bUseKqueue = 0;

extern "C" void ensure_eventmachine (const char *caller = "unknown caller")
{
	if (!EventMachine) {
		const int err_size = 128;
		char err_string[err_size];
		snprintf (err_string, err_size, "eventmachine not initialized: %s", caller);
		#ifdef BUILD_FOR_RUBY
			rb_raise(rb_eRuntimeError, "%s", err_string);
		#else
			throw std::runtime_error (err_string);
		#endif
	}
}

/***********************
evma_initialize_library
***********************/

extern "C" void evma_initialize_library (EMCallback cb)
{
	if (EventMachine)
		#ifdef BUILD_FOR_RUBY
			rb_raise(rb_eRuntimeError, "eventmachine already initialized: evma_initialize_library");
		#else
			throw std::runtime_error ("eventmachine already initialized: evma_initialize_library");
		#endif
	EventMachine = new EventMachine_t (cb);
	if (bUseEpoll)
		EventMachine->_UseEpoll();
	if (bUseKqueue)
		EventMachine->_UseKqueue();
}


/********************
evma_release_library
********************/

extern "C" void evma_release_library()
{
	ensure_eventmachine("evma_release_library");
	delete EventMachine;
	EventMachine = NULL;
}


/****************
evma_run_machine
****************/

extern "C" void evma_run_machine()
{
	ensure_eventmachine("evma_run_machine");
	EventMachine->Run();
}


/**************************
evma_install_oneshot_timer
**************************/

extern "C" const unsigned long evma_install_oneshot_timer (int seconds)
{
	ensure_eventmachine("evma_install_oneshot_timer");
	return EventMachine->InstallOneshotTimer (seconds);
}


/**********************
evma_connect_to_server
**********************/

extern "C" const unsigned long evma_connect_to_server (const char *bind_addr, int bind_port, const char *server, int port)
{
	ensure_eventmachine("evma_connect_to_server");
	return EventMachine->ConnectToServer (bind_addr, bind_port, server, port);
}

/***************************
evma_connect_to_unix_server
***************************/

extern "C" const unsigned long evma_connect_to_unix_server (const char *server)
{
	ensure_eventmachine("evma_connect_to_unix_server");
	return EventMachine->ConnectToUnixServer (server);
}

/**************
evma_attach_fd
**************/

extern "C" const unsigned long evma_attach_fd (int file_descriptor, int watch_mode)
{
	ensure_eventmachine("evma_attach_fd");
	return EventMachine->AttachFD (file_descriptor, watch_mode ? true : false);
}

/**************
evma_detach_fd
**************/

extern "C" int evma_detach_fd (const unsigned long binding)
{
	ensure_eventmachine("evma_detach_fd");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		return EventMachine->DetachFD (ed);
	else
		#ifdef BUILD_FOR_RUBY
			rb_raise(rb_eRuntimeError, "invalid binding to detach");
		#else
			throw std::runtime_error ("invalid binding to detach");
		#endif
			return -1;
}

/************************
evma_get_file_descriptor
************************/

extern "C" int evma_get_file_descriptor (const unsigned long binding)
{
	ensure_eventmachine("evma_get_file_descriptor");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		return ed->GetSocket();
	else
		#ifdef BUILD_FOR_RUBY
			rb_raise(rb_eRuntimeError, "invalid binding to get_fd");
		#else
			throw std::runtime_error ("invalid binding to get_fd");
		#endif
			return -1;
}

/***********************
evma_is_notify_readable
***********************/

extern "C" int evma_is_notify_readable (const unsigned long binding)
{
	ConnectionDescriptor *cd = dynamic_cast <ConnectionDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		return cd->IsNotifyReadable() ? 1 : 0;
	return -1;
}

/************************
evma_set_notify_readable
************************/

extern "C" void evma_set_notify_readable (const unsigned long binding, int mode)
{
	ConnectionDescriptor *cd = dynamic_cast <ConnectionDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		cd->SetNotifyReadable (mode ? true : false);
}

/***********************
evma_is_notify_writable
***********************/

extern "C" int evma_is_notify_writable (const unsigned long binding)
{
	ConnectionDescriptor *cd = dynamic_cast <ConnectionDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		return cd->IsNotifyWritable() ? 1 : 0;
	return -1;
}

/************************
evma_set_notify_writable
************************/

extern "C" void evma_set_notify_writable (const unsigned long binding, int mode)
{
	ConnectionDescriptor *cd = dynamic_cast <ConnectionDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		cd->SetNotifyWritable (mode ? true : false);
}

/**********
evma_pause
**********/

extern "C" int evma_pause (const unsigned long binding)
{
	EventableDescriptor *cd = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		return cd->Pause() ? 1 : 0;

	return 0;
}

/***********
evma_resume
***********/

extern "C" int evma_resume (const unsigned long binding)
{
	EventableDescriptor *cd = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		return cd->Resume() ? 1 : 0;

	return 0;
}

/**************
evma_is_paused
**************/

extern "C" int evma_is_paused (const unsigned long binding)
{
	EventableDescriptor *cd = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		return cd->IsPaused() ? 1 : 0;

	return 0;
}

/************************
evma_num_close_scheduled
************************/

extern "C" int evma_num_close_scheduled ()
{
	return EventMachine->NumCloseScheduled;
}

/**********************
evma_create_tcp_server
**********************/

extern "C" const unsigned long evma_create_tcp_server (const char *address, int port)
{
	ensure_eventmachine("evma_create_tcp_server");
	return EventMachine->CreateTcpServer (address, port);
}

/******************************
evma_create_unix_domain_server
******************************/

extern "C" const unsigned long evma_create_unix_domain_server (const char *filename)
{
	ensure_eventmachine("evma_create_unix_domain_server");
	return EventMachine->CreateUnixDomainServer (filename);
}

/*************************
evma_open_datagram_socket
*************************/

extern "C" const unsigned long evma_open_datagram_socket (const char *address, int port)
{
	ensure_eventmachine("evma_open_datagram_socket");
	return EventMachine->OpenDatagramSocket (address, port);
}

/******************
evma_open_keyboard
******************/

extern "C" const unsigned long evma_open_keyboard()
{
	ensure_eventmachine("evma_open_keyboard");
	return EventMachine->OpenKeyboard();
}

/*******************
evma_watch_filename
*******************/

extern "C" const unsigned long evma_watch_filename (const char *fname)
{
	ensure_eventmachine("evma_watch_filename");
	return EventMachine->WatchFile(fname);
}

/*********************
evma_unwatch_filename
*********************/

extern "C" void evma_unwatch_filename (const unsigned long sig)
{
	ensure_eventmachine("evma_unwatch_file");
	EventMachine->UnwatchFile(sig);
}

/**************
evma_watch_pid
**************/

extern "C" const unsigned long evma_watch_pid (int pid)
{
	ensure_eventmachine("evma_watch_pid");
	return EventMachine->WatchPid(pid);
}

/****************
evma_unwatch_pid
****************/

extern "C" void evma_unwatch_pid (const unsigned long sig)
{
	ensure_eventmachine("evma_unwatch_pid");
	EventMachine->UnwatchPid(sig);
}

/****************************
evma_send_data_to_connection
****************************/

extern "C" int evma_send_data_to_connection (const unsigned long binding, const char *data, int data_length)
{
	ensure_eventmachine("evma_send_data_to_connection");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		return ed->SendOutboundData(data, data_length);
	return -1;
}

/******************
evma_send_datagram
******************/

extern "C" int evma_send_datagram (const unsigned long binding, const char *data, int data_length, const char *address, int port)
{
	ensure_eventmachine("evma_send_datagram");
	DatagramDescriptor *dd = dynamic_cast <DatagramDescriptor*> (Bindable_t::GetObject (binding));
	if (dd)
		return dd->SendOutboundDatagram(data, data_length, address, port);
	return -1;
}


/*********************
evma_close_connection
*********************/

extern "C" void evma_close_connection (const unsigned long binding, int after_writing)
{
	ensure_eventmachine("evma_close_connection");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		ed->ScheduleClose (after_writing ? true : false);
}

/***********************************
evma_report_connection_error_status
***********************************/

extern "C" int evma_report_connection_error_status (const unsigned long binding)
{
	ensure_eventmachine("evma_report_connection_error_status");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		return ed->ReportErrorStatus();
	return -1;
}

/********************
evma_stop_tcp_server
********************/

extern "C" void evma_stop_tcp_server (const unsigned long binding)
{
	ensure_eventmachine("evma_stop_tcp_server");
	AcceptorDescriptor::StopAcceptor (binding);
}


/*****************
evma_stop_machine
*****************/

extern "C" void evma_stop_machine()
{
	ensure_eventmachine("evma_stop_machine");
	EventMachine->ScheduleHalt();
}


/**************
evma_start_tls
**************/

extern "C" void evma_start_tls (const unsigned long binding)
{
	ensure_eventmachine("evma_start_tls");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		ed->StartTls();
}

/******************
evma_set_tls_parms
******************/

extern "C" void evma_set_tls_parms (const unsigned long binding, const char *privatekey_filename, const char *certchain_filename, int verify_peer)
{
	ensure_eventmachine("evma_set_tls_parms");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		ed->SetTlsParms (privatekey_filename, certchain_filename, (verify_peer == 1 ? true : false));
}

/******************
evma_get_peer_cert
******************/

#ifdef WITH_SSL
extern "C" X509 *evma_get_peer_cert (const unsigned long binding)
{
	ensure_eventmachine("evma_get_peer_cert");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed)
		return ed->GetPeerCert();
	return NULL;
}
#endif

/********************
evma_accept_ssl_peer
********************/

#ifdef WITH_SSL
extern "C" void evma_accept_ssl_peer (const unsigned long binding)
{
	ensure_eventmachine("evma_accept_ssl_peer");
	ConnectionDescriptor *cd = dynamic_cast <ConnectionDescriptor*> (Bindable_t::GetObject (binding));
	if (cd)
		cd->AcceptSslPeer();
}
#endif

/*****************
evma_get_peername
*****************/

extern "C" int evma_get_peername (const unsigned long binding, struct sockaddr *sa, socklen_t *len)
{
	ensure_eventmachine("evma_get_peername");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed) {
		return ed->GetPeername (sa, len) ? 1 : 0;
	}
	else
		return 0;
}

/*****************
evma_get_sockname
*****************/

extern "C" int evma_get_sockname (const unsigned long binding, struct sockaddr *sa, socklen_t *len)
{
	ensure_eventmachine("evma_get_sockname");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed) {
		return ed->GetSockname (sa, len) ? 1 : 0;
	}
	else
		return 0;
}

/***********************
evma_get_subprocess_pid
***********************/

extern "C" int evma_get_subprocess_pid (const unsigned long binding, pid_t *pid)
{
	ensure_eventmachine("evma_get_subprocess_pid");
	#ifdef OS_UNIX
	PipeDescriptor *pd = dynamic_cast <PipeDescriptor*> (Bindable_t::GetObject (binding));
	if (pd) {
		return pd->GetSubprocessPid (pid) ? 1 : 0;
	}
	else if (pid && EventMachine->SubprocessPid) {
		*pid = EventMachine->SubprocessPid;
		return 1;
	}
	else
		return 0;
	#else
	return 0;
	#endif
}

/**************************
evma_get_subprocess_status
**************************/

extern "C" int evma_get_subprocess_status (const unsigned long binding, int *status)
{
	ensure_eventmachine("evma_get_subprocess_status");
	if (status) {
		*status = EventMachine->SubprocessExitStatus;
		return 1;
	}
	else
		return 0;
}

/*************************
evma_get_connection_count
*************************/

extern "C" int evma_get_connection_count()
{
	ensure_eventmachine("evma_get_connection_count");
	return EventMachine->GetConnectionCount();
}

/*********************
evma_signal_loopbreak
*********************/

extern "C" void evma_signal_loopbreak()
{
	ensure_eventmachine("evma_signal_loopbreak");
	EventMachine->SignalLoopBreaker();
}



/********************************
evma_get_comm_inactivity_timeout
********************************/

extern "C" float evma_get_comm_inactivity_timeout (const unsigned long binding)
{
	ensure_eventmachine("evma_get_comm_inactivity_timeout");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed) {
		return ((float)ed->GetCommInactivityTimeout() / 1000);
	}
	else
		return 0.0; //Perhaps this should be an exception. Access to an unknown binding.
}

/********************************
evma_set_comm_inactivity_timeout
********************************/

extern "C" int evma_set_comm_inactivity_timeout (const unsigned long binding, float value)
{
	ensure_eventmachine("evma_set_comm_inactivity_timeout");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed) {
		return ed->SetCommInactivityTimeout ((uint64_t)(value * 1000));
	}
	else
		return 0; //Perhaps this should be an exception. Access to an unknown binding.
}


/********************************
evma_get_pending_connect_timeout
********************************/

extern "C" float evma_get_pending_connect_timeout (const unsigned long binding)
{
	ensure_eventmachine("evma_get_pending_connect_timeout");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed) {
		return ((float)ed->GetPendingConnectTimeout() / 1000);
	}
	else
		return 0.0;
}


/********************************
evma_set_pending_connect_timeout
********************************/

extern "C" int evma_set_pending_connect_timeout (const unsigned long binding, float value)
{
	ensure_eventmachine("evma_set_pending_connect_timeout");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	if (ed) {
		return ed->SetPendingConnectTimeout ((uint64_t)(value * 1000));
	}
	else
		return 0;
}


/**********************
evma_set_timer_quantum
**********************/

extern "C" void evma_set_timer_quantum (int interval)
{
	ensure_eventmachine("evma_set_timer_quantum");
	EventMachine->SetTimerQuantum (interval);
}


/************************
evma_get_max_timer_count
************************/

extern "C" int evma_get_max_timer_count()
{
	return EventMachine_t::GetMaxTimerCount();
}


/************************
evma_set_max_timer_count
************************/

extern "C" void evma_set_max_timer_count (int ct)
{
	// This may only be called if the reactor is not running.

	if (EventMachine)
		#ifdef BUILD_FOR_RUBY
			rb_raise(rb_eRuntimeError, "eventmachine already initialized: evma_set_max_timer_count");
		#else
			throw std::runtime_error ("eventmachine already initialized: evma_set_max_timer_count");
		#endif
	EventMachine_t::SetMaxTimerCount (ct);
}

/******************
evma_setuid_string
******************/

extern "C" void evma_setuid_string (const char *username)
{
	// We do NOT need to be running an EM instance because this method is static.
	EventMachine_t::SetuidString (username);
}


/**********
evma_popen
**********/

extern "C" const unsigned long evma_popen (char * const*cmd_strings)
{
	ensure_eventmachine("evma_popen");
	return EventMachine->Socketpair (cmd_strings);
}


/***************************
evma_get_outbound_data_size
***************************/

extern "C" int evma_get_outbound_data_size (const unsigned long binding)
{
	ensure_eventmachine("evma_get_outbound_data_size");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (binding));
	return ed ? ed->GetOutboundDataSize() : 0;
}


/**************
evma_set_epoll
**************/

extern "C" void evma_set_epoll (int use)
{
	bUseEpoll = !!use;
}

/***************
evma_set_kqueue
***************/

extern "C" void evma_set_kqueue (int use)
{
	bUseKqueue = !!use;
}


/**********************
evma_set_rlimit_nofile
**********************/

extern "C" int evma_set_rlimit_nofile (int nofiles)
{
	return EventMachine_t::SetRlimitNofile (nofiles);
}


/*********************************
evma_send_file_data_to_connection
*********************************/

extern "C" int evma_send_file_data_to_connection (const unsigned long binding, const char *filename)
{
	/* This is a sugaring over send_data_to_connection that reads a file into a
	 * locally-allocated buffer, and sends the file data to the remote peer.
	 * Return the number of bytes written to the caller.
	 * TODO, needs to impose a limit on the file size. This is intended only for
	 * small files. (I don't know, maybe 8K or less.) For larger files, use interleaved
	 * I/O to avoid slowing the rest of the system down.
	 * TODO: we should return a code rather than barf, in case of file-not-found.
	 * TODO, does this compile on Windows?
	 * TODO, given that we want this to work only with small files, how about allocating
	 * the buffer on the stack rather than the heap?
	 *
	 * Modified 25Jul07. This now returns -1 on file-too-large; 0 for success, and a positive
	 * errno in case of other errors.
	 *
	 * Contributed by Kirk Haines.
	 */

	char data[32*1024];
	int r;

	ensure_eventmachine("evma_send_file_data_to_connection");

	int Fd = open (filename, O_RDONLY);

	if (Fd < 0)
		return errno;
	// From here on, all early returns MUST close Fd.

	struct stat st;
	if (fstat (Fd, &st)) {
		int e = errno;
		close (Fd);
		return e;
	}

	off_t filesize = st.st_size;
	if (filesize <= 0) {
		close (Fd);
		return 0;
	}
	else if (filesize > (off_t) sizeof(data)) {
		close (Fd);
		return -1;
	}


	r = read (Fd, data, filesize);
	if (r != filesize) {
		int e = errno;
		close (Fd);
		return e;
	}
	evma_send_data_to_connection (binding, data, r);
	close (Fd);

	return 0;
}


/****************
evma_start_proxy
*****************/

extern "C" void evma_start_proxy (const unsigned long from, const unsigned long to, const unsigned long bufsize, const unsigned long length)
{
	ensure_eventmachine("evma_start_proxy");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (from));
	if (ed)
		ed->StartProxy(to, bufsize, length);
}


/***************
evma_stop_proxy
****************/

extern "C" void evma_stop_proxy (const unsigned long from)
{
	ensure_eventmachine("evma_stop_proxy");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (from));
	if (ed)
		ed->StopProxy();
}

/******************
evma_proxied_bytes
*******************/

extern "C" unsigned long evma_proxied_bytes (const unsigned long from)
{
	ensure_eventmachine("evma_proxied_bytes");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (from));
	if (ed)
		return ed->GetProxiedBytes();
	else
		return 0;
}


/***************************
evma_get_last_activity_time
****************************/

extern "C" uint64_t evma_get_last_activity_time(const unsigned long from)
{
	ensure_eventmachine("evma_get_last_activity_time");
	EventableDescriptor *ed = dynamic_cast <EventableDescriptor*> (Bindable_t::GetObject (from));
	if (ed)
		return ed->GetLastActivity();
	else
		return 0;
}


/***************************
evma_get_heartbeat_interval
****************************/

extern "C" float evma_get_heartbeat_interval()
{
	ensure_eventmachine("evma_get_heartbeat_interval");
	return EventMachine->GetHeartbeatInterval();
}


/***************************
evma_set_heartbeat_interval
****************************/

extern "C" int evma_set_heartbeat_interval(float interval)
{
	ensure_eventmachine("evma_set_heartbeat_interval");
	return EventMachine->SetHeartbeatInterval(interval);
}


/**************************
evma_get_current_loop_time
***************************/

extern "C" uint64_t evma_get_current_loop_time()
{
	ensure_eventmachine("evma_get_current_loop_time");
	return EventMachine->GetCurrentLoopTime();
}
