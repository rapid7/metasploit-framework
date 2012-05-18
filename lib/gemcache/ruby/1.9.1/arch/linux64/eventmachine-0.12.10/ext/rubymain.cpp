/*****************************************************************************

$Id$

File:     rubymain.cpp
Date:     06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"
#include "eventmachine.h"
#include <ruby.h>

#ifndef RFLOAT_VALUE
#define RFLOAT_VALUE(arg) RFLOAT(arg)->value
#endif

/*******
Statics
*******/

static VALUE EmModule;
static VALUE EmConnection;

static VALUE EM_eConnectionError;
static VALUE EM_eUnknownTimerFired;
static VALUE EM_eConnectionNotBound;
static VALUE EM_eUnsupported;

static VALUE Intern_at_signature;
static VALUE Intern_at_timers;
static VALUE Intern_at_conns;
static VALUE Intern_at_error_handler;
static VALUE Intern_event_callback;
static VALUE Intern_run_deferred_callbacks;
static VALUE Intern_delete;
static VALUE Intern_call;
static VALUE Intern_receive_data;
static VALUE Intern_ssl_handshake_completed;
static VALUE Intern_ssl_verify_peer;
static VALUE Intern_notify_readable;
static VALUE Intern_notify_writable;
static VALUE Intern_proxy_target_unbound;

static VALUE rb_cProcStatus;

struct em_event {
	unsigned long a1;
	int a2;
	const char *a3;
	unsigned long a4;
};

/****************
t_event_callback
****************/

static void event_callback (struct em_event* e)
{
	const unsigned long a1 = e->a1;
	int a2 = e->a2;
	const char *a3 = e->a3;
	const unsigned long a4 = e->a4;

	if (a2 == EM_CONNECTION_READ) {
		VALUE t = rb_ivar_get (EmModule, Intern_at_conns);
		VALUE q = rb_hash_aref (t, ULONG2NUM (a1));
		if (q == Qnil)
			rb_raise (EM_eConnectionNotBound, "received %lu bytes of data for unknown signature: %lu", a4, a1);
		rb_funcall (q, Intern_receive_data, 1, rb_str_new (a3, a4));
	}
	else if (a2 == EM_CONNECTION_NOTIFY_READABLE) {
		VALUE t = rb_ivar_get (EmModule, Intern_at_conns);
		VALUE q = rb_hash_aref (t, ULONG2NUM (a1));
		if (q == Qnil)
			rb_raise (EM_eConnectionNotBound, "unknown connection: %lu", a1);
		rb_funcall (q, Intern_notify_readable, 0);
	}
	else if (a2 == EM_CONNECTION_NOTIFY_WRITABLE) {
		VALUE t = rb_ivar_get (EmModule, Intern_at_conns);
		VALUE q = rb_hash_aref (t, ULONG2NUM (a1));
		if (q == Qnil)
			rb_raise (EM_eConnectionNotBound, "unknown connection: %lu", a1);
		rb_funcall (q, Intern_notify_writable, 0);
	}
	else if (a2 == EM_LOOPBREAK_SIGNAL) {
		rb_funcall (EmModule, Intern_run_deferred_callbacks, 0);
	}
	else if (a2 == EM_TIMER_FIRED) {
		VALUE t = rb_ivar_get (EmModule, Intern_at_timers);
		VALUE q = rb_funcall (t, Intern_delete, 1, ULONG2NUM (a4));
		if (q == Qnil) {
			rb_raise (EM_eUnknownTimerFired, "no such timer: %lu", a4);
		} else if (q == Qfalse) {
			/* Timer Canceled */
		} else {
			rb_funcall (q, Intern_call, 0);
		}
	}
	#ifdef WITH_SSL
	else if (a2 == EM_SSL_HANDSHAKE_COMPLETED) {
		VALUE t = rb_ivar_get (EmModule, Intern_at_conns);
		VALUE q = rb_hash_aref (t, ULONG2NUM (a1));
		if (q == Qnil)
			rb_raise (EM_eConnectionNotBound, "unknown connection: %lu", a1);
		rb_funcall (q, Intern_ssl_handshake_completed, 0);
	}
	else if (a2 == EM_SSL_VERIFY) {
		VALUE t = rb_ivar_get (EmModule, Intern_at_conns);
		VALUE q = rb_hash_aref (t, ULONG2NUM (a1));
		if (q == Qnil)
			rb_raise (EM_eConnectionNotBound, "unknown connection: %lu", a1);
		VALUE r = rb_funcall (q, Intern_ssl_verify_peer, 1, rb_str_new(a3, a4));
		if (RTEST(r))
			evma_accept_ssl_peer (a1);
	}
	#endif
	else if (a2 == EM_PROXY_TARGET_UNBOUND) {
		VALUE t = rb_ivar_get (EmModule, Intern_at_conns);
		VALUE q = rb_hash_aref (t, ULONG2NUM (a1));
		if (q == Qnil)
			rb_raise (EM_eConnectionNotBound, "unknown connection: %lu", a1);
		rb_funcall (q, Intern_proxy_target_unbound, 0);
	}
	else
		rb_funcall (EmModule, Intern_event_callback, 3, ULONG2NUM(a1), INT2FIX(a2), a3 ? rb_str_new(a3,a4) : ULONG2NUM(a4));
}

/*******************
event_error_handler
*******************/

static void event_error_handler(VALUE unused, VALUE err)
{
	VALUE error_handler = rb_ivar_get(EmModule, Intern_at_error_handler);
	rb_funcall (error_handler, Intern_call, 1, err);
}

/**********************
event_callback_wrapper
**********************/

static void event_callback_wrapper (const unsigned long a1, int a2, const char *a3, const unsigned long a4)
{
	struct em_event e;
	e.a1 = a1;
	e.a2 = a2;
	e.a3 = a3;
	e.a4 = a4;

	if (!rb_ivar_defined(EmModule, Intern_at_error_handler))
		event_callback(&e);
	else
		rb_rescue((VALUE (*)(ANYARGS))event_callback, (VALUE)&e, (VALUE (*)(ANYARGS))event_error_handler, Qnil);
}

/**************************
t_initialize_event_machine
**************************/

static VALUE t_initialize_event_machine (VALUE self)
{
	evma_initialize_library (event_callback_wrapper);
	return Qnil;
}



/*****************************
t_run_machine_without_threads
*****************************/

static VALUE t_run_machine_without_threads (VALUE self)
{
	evma_run_machine();
	return Qnil;
}


/*******************
t_add_oneshot_timer
*******************/

static VALUE t_add_oneshot_timer (VALUE self, VALUE interval)
{
	const unsigned long f = evma_install_oneshot_timer (FIX2INT (interval));
	if (!f)
		rb_raise (rb_eRuntimeError, "ran out of timers; use #set_max_timers to increase limit");
	return ULONG2NUM (f);
}


/**************
t_start_server
**************/

static VALUE t_start_server (VALUE self, VALUE server, VALUE port)
{
	const unsigned long f = evma_create_tcp_server (StringValuePtr(server), FIX2INT(port));
	if (!f)
		rb_raise (rb_eRuntimeError, "no acceptor");
	return ULONG2NUM (f);
}

/*************
t_stop_server
*************/

static VALUE t_stop_server (VALUE self, VALUE signature)
{
	evma_stop_tcp_server (NUM2ULONG (signature));
	return Qnil;
}


/*******************
t_start_unix_server
*******************/

static VALUE t_start_unix_server (VALUE self, VALUE filename)
{
	const unsigned long f = evma_create_unix_domain_server (StringValuePtr(filename));
	if (!f)
		rb_raise (rb_eRuntimeError, "no unix-domain acceptor");
	return ULONG2NUM (f);
}



/***********
t_send_data
***********/

static VALUE t_send_data (VALUE self, VALUE signature, VALUE data, VALUE data_length)
{
	int b = evma_send_data_to_connection (NUM2ULONG (signature), StringValuePtr (data), FIX2INT (data_length));
	return INT2NUM (b);
}


/***********
t_start_tls
***********/

static VALUE t_start_tls (VALUE self, VALUE signature)
{
	evma_start_tls (NUM2ULONG (signature));
	return Qnil;
}

/***************
t_set_tls_parms
***************/

static VALUE t_set_tls_parms (VALUE self, VALUE signature, VALUE privkeyfile, VALUE certchainfile, VALUE verify_peer)
{
	/* set_tls_parms takes a series of positional arguments for specifying such things
	 * as private keys and certificate chains.
	 * It's expected that the parameter list will grow as we add more supported features.
	 * ALL of these parameters are optional, and can be specified as empty or NULL strings.
	 */
	evma_set_tls_parms (NUM2ULONG (signature), StringValuePtr (privkeyfile), StringValuePtr (certchainfile), (verify_peer == Qtrue ? 1 : 0));
	return Qnil;
}

/***************
t_get_peer_cert
***************/

static VALUE t_get_peer_cert (VALUE self, VALUE signature)
{
	VALUE ret = Qnil;

	#ifdef WITH_SSL
	X509 *cert = NULL;
	BUF_MEM *buf;
	BIO *out;

	cert = evma_get_peer_cert (NUM2ULONG (signature));

	if (cert != NULL) {
		out = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(out, cert);
		BIO_get_mem_ptr(out, &buf);
		ret = rb_str_new(buf->data, buf->length);
		X509_free(cert);
		BUF_MEM_free(buf);
	}
	#endif

	return ret;
}

/**************
t_get_peername
**************/

static VALUE t_get_peername (VALUE self, VALUE signature)
{
	struct sockaddr s;
	if (evma_get_peername (NUM2ULONG (signature), &s)) {
		return rb_str_new ((const char*)&s, sizeof(s));
	}

	return Qnil;
}

/**************
t_get_sockname
**************/

static VALUE t_get_sockname (VALUE self, VALUE signature)
{
	struct sockaddr s;
	if (evma_get_sockname (NUM2ULONG (signature), &s)) {
		return rb_str_new ((const char*)&s, sizeof(s));
	}

	return Qnil;
}

/********************
t_get_subprocess_pid
********************/

static VALUE t_get_subprocess_pid (VALUE self, VALUE signature)
{
	pid_t pid;
	if (evma_get_subprocess_pid (NUM2ULONG (signature), &pid)) {
		return INT2NUM (pid);
	}

	return Qnil;
}

/***********************
t_get_subprocess_status
***********************/

static VALUE t_get_subprocess_status (VALUE self, VALUE signature)
{
	VALUE proc_status = Qnil;

	int status;
	pid_t pid;

	if (evma_get_subprocess_status (NUM2ULONG (signature), &status)) {
		if (evma_get_subprocess_pid (NUM2ULONG (signature), &pid)) {
			proc_status = rb_obj_alloc(rb_cProcStatus);
			rb_iv_set(proc_status, "status", INT2FIX(status));
			rb_iv_set(proc_status, "pid", INT2FIX(pid));
		}
	}

	return proc_status;
}

/**********************
t_get_connection_count
**********************/

static VALUE t_get_connection_count (VALUE self)
{
	return INT2NUM(evma_get_connection_count());
}

/*****************************
t_get_comm_inactivity_timeout
*****************************/

static VALUE t_get_comm_inactivity_timeout (VALUE self, VALUE signature)
{
	return rb_float_new(evma_get_comm_inactivity_timeout(NUM2ULONG (signature)));
}

/*****************************
t_set_comm_inactivity_timeout
*****************************/

static VALUE t_set_comm_inactivity_timeout (VALUE self, VALUE signature, VALUE timeout)
{
	float ti = RFLOAT_VALUE(timeout);
	if (evma_set_comm_inactivity_timeout (NUM2ULONG (signature), ti));
		return Qtrue;
	return Qfalse;
}

/*****************************
t_get_pending_connect_timeout
*****************************/

static VALUE t_get_pending_connect_timeout (VALUE self, VALUE signature)
{
	return rb_float_new(evma_get_pending_connect_timeout(NUM2ULONG (signature)));
}

/*****************************
t_set_pending_connect_timeout
*****************************/

static VALUE t_set_pending_connect_timeout (VALUE self, VALUE signature, VALUE timeout)
{
	float ti = RFLOAT_VALUE(timeout);
	if (evma_set_pending_connect_timeout (NUM2ULONG (signature), ti));
		return Qtrue;
	return Qfalse;
}

/***************
t_send_datagram
***************/

static VALUE t_send_datagram (VALUE self, VALUE signature, VALUE data, VALUE data_length, VALUE address, VALUE port)
{
	int b = evma_send_datagram (NUM2ULONG (signature), StringValuePtr (data), FIX2INT (data_length), StringValuePtr(address), FIX2INT(port));
	return INT2NUM (b);
}


/******************
t_close_connection
******************/

static VALUE t_close_connection (VALUE self, VALUE signature, VALUE after_writing)
{
	evma_close_connection (NUM2ULONG (signature), ((after_writing == Qtrue) ? 1 : 0));
	return Qnil;
}

/********************************
t_report_connection_error_status
********************************/

static VALUE t_report_connection_error_status (VALUE self, VALUE signature)
{
	int b = evma_report_connection_error_status (NUM2ULONG (signature));
	return INT2NUM (b);
}



/****************
t_connect_server
****************/

static VALUE t_connect_server (VALUE self, VALUE server, VALUE port)
{
	// Avoid FIX2INT in this case, because it doesn't deal with type errors properly.
	// Specifically, if the value of port comes in as a string rather than an integer,
	// NUM2INT will throw a type error, but FIX2INT will generate garbage.

	try {
		const unsigned long f = evma_connect_to_server (NULL, 0, StringValuePtr(server), NUM2INT(port));
		if (!f)
			rb_raise (EM_eConnectionError, "no connection");
		return ULONG2NUM (f);
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, e.what());
	}
}

/*********************
t_bind_connect_server
*********************/

static VALUE t_bind_connect_server (VALUE self, VALUE bind_addr, VALUE bind_port, VALUE server, VALUE port)
{
	// Avoid FIX2INT in this case, because it doesn't deal with type errors properly.
	// Specifically, if the value of port comes in as a string rather than an integer,
	// NUM2INT will throw a type error, but FIX2INT will generate garbage.

	try {
		const unsigned long f = evma_connect_to_server (StringValuePtr(bind_addr), NUM2INT(bind_port), StringValuePtr(server), NUM2INT(port));
		if (!f)
			rb_raise (EM_eConnectionError, "no connection");
		return ULONG2NUM (f);
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, e.what());
	}
}

/*********************
t_connect_unix_server
*********************/

static VALUE t_connect_unix_server (VALUE self, VALUE serversocket)
{
	const unsigned long f = evma_connect_to_unix_server (StringValuePtr(serversocket));
	if (!f)
		rb_raise (rb_eRuntimeError, "no connection");
	return ULONG2NUM (f);
}

/***********
t_attach_fd
***********/

static VALUE t_attach_fd (VALUE self, VALUE file_descriptor, VALUE watch_mode)
{
	const unsigned long f = evma_attach_fd (NUM2INT(file_descriptor), watch_mode == Qtrue);
	if (!f)
		rb_raise (rb_eRuntimeError, "no connection");
	return ULONG2NUM (f);
}

/***********
t_detach_fd
***********/

static VALUE t_detach_fd (VALUE self, VALUE signature)
{
	return INT2NUM(evma_detach_fd (NUM2ULONG (signature)));
}

/**************
t_get_sock_opt
**************/

static VALUE t_get_sock_opt (VALUE self, VALUE signature, VALUE lev, VALUE optname)
{
	int fd = evma_get_file_descriptor (NUM2ULONG (signature));
	int level = NUM2INT(lev), option = NUM2INT(optname);
	socklen_t len = 128;
	char buf[128];

	if (getsockopt(fd, level, option, buf, &len) < 0)
		rb_sys_fail("getsockopt");

	return rb_str_new(buf, len);
}

/********************
t_is_notify_readable
********************/

static VALUE t_is_notify_readable (VALUE self, VALUE signature)
{
	return evma_is_notify_readable(NUM2ULONG (signature)) ? Qtrue : Qfalse;
}

/*********************
t_set_notify_readable
*********************/

static VALUE t_set_notify_readable (VALUE self, VALUE signature, VALUE mode)
{
	evma_set_notify_readable(NUM2ULONG (signature), mode == Qtrue);
	return Qnil;
}

/********************
t_is_notify_readable
********************/

static VALUE t_is_notify_writable (VALUE self, VALUE signature)
{
	return evma_is_notify_writable(NUM2ULONG (signature)) ? Qtrue : Qfalse;
}

/*********************
t_set_notify_writable
*********************/

static VALUE t_set_notify_writable (VALUE self, VALUE signature, VALUE mode)
{
	evma_set_notify_writable(NUM2ULONG (signature), mode == Qtrue);
	return Qnil;
}

/*******
t_pause
*******/

static VALUE t_pause (VALUE self, VALUE signature)
{
	return evma_pause(NUM2ULONG (signature)) ? Qtrue : Qfalse;
}

/********
t_resume
********/

static VALUE t_resume (VALUE self, VALUE signature)
{
	return evma_resume(NUM2ULONG (signature)) ? Qtrue : Qfalse;
}

/**********
t_paused_p
**********/

static VALUE t_paused_p (VALUE self, VALUE signature)
{
	return evma_is_paused(NUM2ULONG (signature)) ? Qtrue : Qfalse;
}

/*****************
t_open_udp_socket
*****************/

static VALUE t_open_udp_socket (VALUE self, VALUE server, VALUE port)
{
	const unsigned long f = evma_open_datagram_socket (StringValuePtr(server), FIX2INT(port));
	if (!f)
		rb_raise (rb_eRuntimeError, "no datagram socket");
	return ULONG2NUM (f);
}



/*****************
t_release_machine
*****************/

static VALUE t_release_machine (VALUE self)
{
	evma_release_library();
	return Qnil;
}


/******
t_stop
******/

static VALUE t_stop (VALUE self)
{
	evma_stop_machine();
	return Qnil;
}

/******************
t_signal_loopbreak
******************/

static VALUE t_signal_loopbreak (VALUE self)
{
	evma_signal_loopbreak();
	return Qnil;
}

/**************
t_library_type
**************/

static VALUE t_library_type (VALUE self)
{
	return rb_eval_string (":extension");
}



/*******************
t_set_timer_quantum
*******************/

static VALUE t_set_timer_quantum (VALUE self, VALUE interval)
{
  evma_set_timer_quantum (FIX2INT (interval));
  return Qnil;
}

/********************
t_get_max_timer_count
********************/

static VALUE t_get_max_timer_count (VALUE self)
{
  return INT2FIX (evma_get_max_timer_count());
}

/********************
t_set_max_timer_count
********************/

static VALUE t_set_max_timer_count (VALUE self, VALUE ct)
{
  evma_set_max_timer_count (FIX2INT (ct));
  return Qnil;
}

/***************
t_setuid_string
***************/

static VALUE t_setuid_string (VALUE self, VALUE username)
{
  evma_setuid_string (StringValuePtr (username));
  return Qnil;
}



/*************
t__write_file
*************/

static VALUE t__write_file (VALUE self, VALUE filename)
{
	const unsigned long f = evma__write_file (StringValuePtr (filename));
	if (!f)
		rb_raise (rb_eRuntimeError, "file not opened");
	return ULONG2NUM (f);
}

/**************
t_invoke_popen
**************/

static VALUE t_invoke_popen (VALUE self, VALUE cmd)
{
	// 1.8.7+
	#ifdef RARRAY_LEN
		int len = RARRAY_LEN(cmd);
	#else
		int len = RARRAY (cmd)->len;
	#endif
	if (len > 98)
		rb_raise (rb_eRuntimeError, "too many arguments to popen");
	char *strings [100];
	for (int i=0; i < len; i++) {
		VALUE ix = INT2FIX (i);
		VALUE s = rb_ary_aref (1, &ix, cmd);
		strings[i] = StringValuePtr (s);
	}
	strings[len] = NULL;

	const unsigned long f = evma_popen (strings);
	if (!f) {
		char *err = strerror (errno);
		char buf[100];
		memset (buf, 0, sizeof(buf));
		snprintf (buf, sizeof(buf)-1, "no popen: %s", (err?err:"???"));
		rb_raise (rb_eRuntimeError, "%s", buf);
	}
	return ULONG2NUM (f);
}


/***************
t_read_keyboard
***************/

static VALUE t_read_keyboard (VALUE self)
{
	const unsigned long f = evma_open_keyboard();
	if (!f)
		rb_raise (rb_eRuntimeError, "no keyboard reader");
	return ULONG2NUM (f);
}


/****************
t_watch_filename
****************/

static VALUE t_watch_filename (VALUE self, VALUE fname)
{
	try {
		return ULONG2NUM(evma_watch_filename(StringValuePtr(fname)));
	} catch (std::runtime_error e) {
		rb_sys_fail(e.what());
	}
}


/******************
t_unwatch_filename
******************/

static VALUE t_unwatch_filename (VALUE self, VALUE sig)
{
	evma_unwatch_filename(NUM2ULONG (sig));
	return Qnil;
}


/***********
t_watch_pid
***********/

static VALUE t_watch_pid (VALUE self, VALUE pid)
{
	try {
		return ULONG2NUM(evma_watch_pid(NUM2INT(pid)));
	} catch (std::runtime_error e) {
		rb_sys_fail(e.what());
	}
}


/*************
t_unwatch_pid
*************/

static VALUE t_unwatch_pid (VALUE self, VALUE sig)
{
	evma_unwatch_pid(NUM2ULONG (sig));
	return Qnil;
}


/**********
t__epoll_p
**********/

static VALUE t__epoll_p (VALUE self)
{
  #ifdef HAVE_EPOLL
  return Qtrue;
  #else
  return Qfalse;
  #endif
}

/********
t__epoll
********/

static VALUE t__epoll (VALUE self)
{
	evma_set_epoll (1);
	return Qtrue;
}

/***********
t__epoll_set
***********/

static VALUE t__epoll_set (VALUE self, VALUE val)
{
	if (t__epoll_p(self) == Qfalse)
		rb_raise (EM_eUnsupported, "epoll is not supported on this platform");

	evma_set_epoll (val == Qtrue ? 1 : 0);
	return val;
}


/***********
t__kqueue_p
***********/

static VALUE t__kqueue_p (VALUE self)
{
  #ifdef HAVE_KQUEUE
  return Qtrue;
  #else
  return Qfalse;
  #endif
}

/*********
t__kqueue
*********/

static VALUE t__kqueue (VALUE self)
{
	evma_set_kqueue (1);
	return Qtrue;
}

/*************
t__kqueue_set
*************/

static VALUE t__kqueue_set (VALUE self, VALUE val)
{
	if (t__kqueue_p(self) == Qfalse)
		rb_raise (EM_eUnsupported, "kqueue is not supported on this platform");

	evma_set_kqueue (val == Qtrue ? 1 : 0);
	return val;
}


/********
t__ssl_p
********/

static VALUE t__ssl_p (VALUE self)
{
  #ifdef WITH_SSL
  return Qtrue;
  #else
  return Qfalse;
  #endif
}


/****************
t_send_file_data
****************/

static VALUE t_send_file_data (VALUE self, VALUE signature, VALUE filename)
{

	/* The current implementation of evma_send_file_data_to_connection enforces a strict
	 * upper limit on the file size it will transmit (currently 32K). The function returns
	 * zero on success, -1 if the requested file exceeds its size limit, and a positive
	 * number for other errors.
	 * TODO: Positive return values are actually errno's, which is probably the wrong way to
	 * do this. For one thing it's ugly. For another, we can't be sure zero is never a real errno.
	 */

	int b = evma_send_file_data_to_connection (NUM2ULONG (signature), StringValuePtr(filename));
	if (b == -1)
		rb_raise(rb_eRuntimeError, "File too large.  send_file_data() supports files under 32k.");
	if (b > 0) {
		char *err = strerror (b);
		char buf[1024];
		memset (buf, 0, sizeof(buf));
		snprintf (buf, sizeof(buf)-1, ": %s %s", StringValuePtr(filename),(err?err:"???"));

		rb_raise (rb_eIOError, "%s", buf);
	}

	return INT2NUM (0);
}


/*******************
t_set_rlimit_nofile
*******************/

static VALUE t_set_rlimit_nofile (VALUE self, VALUE arg)
{
	arg = (NIL_P(arg)) ? -1 : NUM2INT (arg);
	return INT2NUM (evma_set_rlimit_nofile (arg));
}

/***************************
conn_get_outbound_data_size
***************************/

static VALUE conn_get_outbound_data_size (VALUE self)
{
	VALUE sig = rb_ivar_get (self, Intern_at_signature);
	return INT2NUM (evma_get_outbound_data_size (NUM2ULONG (sig)));
}


/******************************
conn_associate_callback_target
******************************/

static VALUE conn_associate_callback_target (VALUE self, VALUE sig)
{
	// No-op for the time being.
	return Qnil;
}


/***************
t_get_loop_time
****************/

static VALUE t_get_loop_time (VALUE self)
{
#ifndef HAVE_RB_TIME_NEW
  static VALUE cTime = rb_path2class("Time");
  static ID at = rb_intern("at");
#endif

  if (gCurrentLoopTime != 0) {
#ifndef HAVE_RB_TIME_NEW
    return rb_funcall(cTime, at, 2, INT2NUM(gCurrentLoopTime / 1000000), INT2NUM(gCurrentLoopTime % 1000000));
#else
    return rb_time_new(gCurrentLoopTime / 1000000, gCurrentLoopTime % 1000000);
#endif
  }
  return Qnil;
}


/*************
t_start_proxy
**************/

static VALUE t_start_proxy (VALUE self, VALUE from, VALUE to, VALUE bufsize)
{
	evma_start_proxy(NUM2ULONG (from), NUM2ULONG (to), NUM2ULONG(bufsize));
	return Qnil;
}


/************
t_stop_proxy
*************/

static VALUE t_stop_proxy (VALUE self, VALUE from)
{
	evma_stop_proxy(NUM2ULONG (from));
	return Qnil;
}


/************************
t_get_heartbeat_interval
*************************/

static VALUE t_get_heartbeat_interval (VALUE self)
{
	return rb_float_new(evma_get_heartbeat_interval());
}


/************************
t_set_heartbeat_interval
*************************/

static VALUE t_set_heartbeat_interval (VALUE self, VALUE interval)
{
	float iv = RFLOAT_VALUE(interval);
	if (evma_set_heartbeat_interval(iv))
		return Qtrue;
	return Qfalse;
}


/*********************
Init_rubyeventmachine
*********************/

extern "C" void Init_rubyeventmachine()
{
	// Lookup Process::Status for get_subprocess_status
	VALUE rb_mProcess = rb_const_get(rb_cObject, rb_intern("Process"));
	rb_cProcStatus = rb_const_get(rb_mProcess, rb_intern("Status"));

	// Tuck away some symbol values so we don't have to look 'em up every time we need 'em.
	Intern_at_signature = rb_intern ("@signature");
	Intern_at_timers = rb_intern ("@timers");
	Intern_at_conns = rb_intern ("@conns");
	Intern_at_error_handler = rb_intern("@error_handler");

	Intern_event_callback = rb_intern ("event_callback");
	Intern_run_deferred_callbacks = rb_intern ("run_deferred_callbacks");
	Intern_delete = rb_intern ("delete");
	Intern_call = rb_intern ("call");
	Intern_receive_data = rb_intern ("receive_data");
	Intern_ssl_handshake_completed = rb_intern ("ssl_handshake_completed");
	Intern_ssl_verify_peer = rb_intern ("ssl_verify_peer");
	Intern_notify_readable = rb_intern ("notify_readable");
	Intern_notify_writable = rb_intern ("notify_writable");
	Intern_proxy_target_unbound = rb_intern ("proxy_target_unbound");

	// INCOMPLETE, we need to define class Connections inside module EventMachine
	// run_machine and run_machine_without_threads are now identical.
	// Must deprecate the without_threads variant.
	EmModule = rb_define_module ("EventMachine");
	EmConnection = rb_define_class_under (EmModule, "Connection", rb_cObject);

	rb_define_class_under (EmModule, "NoHandlerForAcceptedConnection", rb_eRuntimeError);
	EM_eConnectionError = rb_define_class_under (EmModule, "ConnectionError", rb_eRuntimeError);
	EM_eConnectionNotBound = rb_define_class_under (EmModule, "ConnectionNotBound", rb_eRuntimeError);
	EM_eUnknownTimerFired = rb_define_class_under (EmModule, "UnknownTimerFired", rb_eRuntimeError);
	EM_eUnsupported = rb_define_class_under (EmModule, "Unsupported", rb_eRuntimeError);

	rb_define_module_function (EmModule, "initialize_event_machine", (VALUE(*)(...))t_initialize_event_machine, 0);
	rb_define_module_function (EmModule, "run_machine", (VALUE(*)(...))t_run_machine_without_threads, 0);
	rb_define_module_function (EmModule, "run_machine_without_threads", (VALUE(*)(...))t_run_machine_without_threads, 0);
	rb_define_module_function (EmModule, "add_oneshot_timer", (VALUE(*)(...))t_add_oneshot_timer, 1);
	rb_define_module_function (EmModule, "start_tcp_server", (VALUE(*)(...))t_start_server, 2);
	rb_define_module_function (EmModule, "stop_tcp_server", (VALUE(*)(...))t_stop_server, 1);
	rb_define_module_function (EmModule, "start_unix_server", (VALUE(*)(...))t_start_unix_server, 1);
	rb_define_module_function (EmModule, "set_tls_parms", (VALUE(*)(...))t_set_tls_parms, 4);
	rb_define_module_function (EmModule, "start_tls", (VALUE(*)(...))t_start_tls, 1);
	rb_define_module_function (EmModule, "get_peer_cert", (VALUE(*)(...))t_get_peer_cert, 1);
	rb_define_module_function (EmModule, "send_data", (VALUE(*)(...))t_send_data, 3);
	rb_define_module_function (EmModule, "send_datagram", (VALUE(*)(...))t_send_datagram, 5);
	rb_define_module_function (EmModule, "close_connection", (VALUE(*)(...))t_close_connection, 2);
	rb_define_module_function (EmModule, "report_connection_error_status", (VALUE(*)(...))t_report_connection_error_status, 1);
	rb_define_module_function (EmModule, "connect_server", (VALUE(*)(...))t_connect_server, 2);
	rb_define_module_function (EmModule, "bind_connect_server", (VALUE(*)(...))t_bind_connect_server, 4);
	rb_define_module_function (EmModule, "connect_unix_server", (VALUE(*)(...))t_connect_unix_server, 1);

	rb_define_module_function (EmModule, "attach_fd", (VALUE (*)(...))t_attach_fd, 2);
	rb_define_module_function (EmModule, "detach_fd", (VALUE (*)(...))t_detach_fd, 1);
	rb_define_module_function (EmModule, "get_sock_opt", (VALUE (*)(...))t_get_sock_opt, 3);
	rb_define_module_function (EmModule, "set_notify_readable", (VALUE (*)(...))t_set_notify_readable, 2);
	rb_define_module_function (EmModule, "set_notify_writable", (VALUE (*)(...))t_set_notify_writable, 2);
	rb_define_module_function (EmModule, "is_notify_readable", (VALUE (*)(...))t_is_notify_readable, 1);
	rb_define_module_function (EmModule, "is_notify_writable", (VALUE (*)(...))t_is_notify_writable, 1);

	rb_define_module_function (EmModule, "pause_connection", (VALUE (*)(...))t_pause, 1);
	rb_define_module_function (EmModule, "resume_connection", (VALUE (*)(...))t_resume, 1);
	rb_define_module_function (EmModule, "connection_paused?", (VALUE (*)(...))t_paused_p, 1);

	rb_define_module_function (EmModule, "start_proxy", (VALUE (*)(...))t_start_proxy, 3);
	rb_define_module_function (EmModule, "stop_proxy", (VALUE (*)(...))t_stop_proxy, 1);

	rb_define_module_function (EmModule, "watch_filename", (VALUE (*)(...))t_watch_filename, 1);
	rb_define_module_function (EmModule, "unwatch_filename", (VALUE (*)(...))t_unwatch_filename, 1);

	rb_define_module_function (EmModule, "watch_pid", (VALUE (*)(...))t_watch_pid, 1);
	rb_define_module_function (EmModule, "unwatch_pid", (VALUE (*)(...))t_unwatch_pid, 1);

	rb_define_module_function (EmModule, "current_time", (VALUE(*)(...))t_get_loop_time, 0);

	rb_define_module_function (EmModule, "open_udp_socket", (VALUE(*)(...))t_open_udp_socket, 2);
	rb_define_module_function (EmModule, "read_keyboard", (VALUE(*)(...))t_read_keyboard, 0);
	rb_define_module_function (EmModule, "release_machine", (VALUE(*)(...))t_release_machine, 0);
	rb_define_module_function (EmModule, "stop", (VALUE(*)(...))t_stop, 0);
	rb_define_module_function (EmModule, "signal_loopbreak", (VALUE(*)(...))t_signal_loopbreak, 0);
	rb_define_module_function (EmModule, "library_type", (VALUE(*)(...))t_library_type, 0);
	rb_define_module_function (EmModule, "set_timer_quantum", (VALUE(*)(...))t_set_timer_quantum, 1);
	rb_define_module_function (EmModule, "get_max_timer_count", (VALUE(*)(...))t_get_max_timer_count, 0);
	rb_define_module_function (EmModule, "set_max_timer_count", (VALUE(*)(...))t_set_max_timer_count, 1);
	rb_define_module_function (EmModule, "setuid_string", (VALUE(*)(...))t_setuid_string, 1);
	rb_define_module_function (EmModule, "invoke_popen", (VALUE(*)(...))t_invoke_popen, 1);
	rb_define_module_function (EmModule, "send_file_data", (VALUE(*)(...))t_send_file_data, 2);
	rb_define_module_function (EmModule, "get_heartbeat_interval", (VALUE(*)(...))t_get_heartbeat_interval, 0);
	rb_define_module_function (EmModule, "set_heartbeat_interval", (VALUE(*)(...))t_set_heartbeat_interval, 1);

	// Provisional:
	rb_define_module_function (EmModule, "_write_file", (VALUE(*)(...))t__write_file, 1);

	rb_define_module_function (EmModule, "get_peername", (VALUE(*)(...))t_get_peername, 1);
	rb_define_module_function (EmModule, "get_sockname", (VALUE(*)(...))t_get_sockname, 1);
	rb_define_module_function (EmModule, "get_subprocess_pid", (VALUE(*)(...))t_get_subprocess_pid, 1);
	rb_define_module_function (EmModule, "get_subprocess_status", (VALUE(*)(...))t_get_subprocess_status, 1);
	rb_define_module_function (EmModule, "get_comm_inactivity_timeout", (VALUE(*)(...))t_get_comm_inactivity_timeout, 1);
	rb_define_module_function (EmModule, "set_comm_inactivity_timeout", (VALUE(*)(...))t_set_comm_inactivity_timeout, 2);
	rb_define_module_function (EmModule, "get_pending_connect_timeout", (VALUE(*)(...))t_get_pending_connect_timeout, 1);
	rb_define_module_function (EmModule, "set_pending_connect_timeout", (VALUE(*)(...))t_set_pending_connect_timeout, 2);
	rb_define_module_function (EmModule, "set_rlimit_nofile", (VALUE(*)(...))t_set_rlimit_nofile, 1);
	rb_define_module_function (EmModule, "get_connection_count", (VALUE(*)(...))t_get_connection_count, 0);

	rb_define_module_function (EmModule, "epoll", (VALUE(*)(...))t__epoll, 0);
	rb_define_module_function (EmModule, "epoll=", (VALUE(*)(...))t__epoll_set, 1);
	rb_define_module_function (EmModule, "epoll?", (VALUE(*)(...))t__epoll_p, 0);

	rb_define_module_function (EmModule, "kqueue", (VALUE(*)(...))t__kqueue, 0);
	rb_define_module_function (EmModule, "kqueue=", (VALUE(*)(...))t__kqueue_set, 1);
	rb_define_module_function (EmModule, "kqueue?", (VALUE(*)(...))t__kqueue_p, 0);

	rb_define_module_function (EmModule, "ssl?", (VALUE(*)(...))t__ssl_p, 0);

	rb_define_method (EmConnection, "get_outbound_data_size", (VALUE(*)(...))conn_get_outbound_data_size, 0);
	rb_define_method (EmConnection, "associate_callback_target", (VALUE(*)(...))conn_associate_callback_target, 1);

	rb_define_const (EmModule, "TimerFired", INT2NUM(100));
	rb_define_const (EmModule, "ConnectionData", INT2NUM(101));
	rb_define_const (EmModule, "ConnectionUnbound", INT2NUM(102));
	rb_define_const (EmModule, "ConnectionAccepted", INT2NUM(103));
	rb_define_const (EmModule, "ConnectionCompleted", INT2NUM(104));
	rb_define_const (EmModule, "LoopbreakSignalled", INT2NUM(105));

	rb_define_const (EmModule, "ConnectionNotifyReadable", INT2NUM(106));
	rb_define_const (EmModule, "ConnectionNotifyWritable", INT2NUM(107));

	rb_define_const (EmModule, "SslHandshakeCompleted", INT2NUM(108));

}

