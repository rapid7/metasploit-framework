/*****************************************************************************

$Id$

File:     eventmachine.h
Date:     15Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#ifndef __EVMA_EventMachine__H_
#define __EVMA_EventMachine__H_

#if __cplusplus
extern "C" {
#endif

	enum { // Event names
		EM_TIMER_FIRED = 100,
		EM_CONNECTION_READ = 101,
		EM_CONNECTION_UNBOUND = 102,
		EM_CONNECTION_ACCEPTED = 103,
		EM_CONNECTION_COMPLETED = 104,
		EM_LOOPBREAK_SIGNAL = 105,
		EM_CONNECTION_NOTIFY_READABLE = 106,
		EM_CONNECTION_NOTIFY_WRITABLE = 107,
		EM_SSL_HANDSHAKE_COMPLETED = 108,
		EM_SSL_VERIFY = 109,
		EM_PROXY_TARGET_UNBOUND = 110,
		EM_PROXY_COMPLETED = 111

	};

	void evma_initialize_library (EMCallback);
	void evma_run_machine();
	void evma_release_library();
	const unsigned long evma_install_oneshot_timer (int seconds);
	const unsigned long evma_connect_to_server (const char *bind_addr, int bind_port, const char *server, int port);
	const unsigned long evma_connect_to_unix_server (const char *server);

	const unsigned long evma_attach_fd (int file_descriptor, int watch_mode);
	int evma_detach_fd (const unsigned long binding);
	int evma_get_file_descriptor (const unsigned long binding);
	int evma_is_notify_readable (const unsigned long binding);
	void evma_set_notify_readable (const unsigned long binding, int mode);
	int evma_is_notify_writable (const unsigned long binding);
	void evma_set_notify_writable (const unsigned long binding, int mode);

	int evma_pause(const unsigned long binding);
	int evma_is_paused(const unsigned long binding);
	int evma_resume(const unsigned long binding);

    int evma_num_close_scheduled();

	void evma_stop_tcp_server (const unsigned long signature);
	const unsigned long evma_create_tcp_server (const char *address, int port);
	const unsigned long evma_create_unix_domain_server (const char *filename);
	const unsigned long evma_open_datagram_socket (const char *server, int port);
	const unsigned long evma_open_keyboard();
	void evma_set_tls_parms (const unsigned long binding, const char *privatekey_filename, const char *certchain_filenane, int verify_peer);
	void evma_start_tls (const unsigned long binding);

	#ifdef WITH_SSL
	X509 *evma_get_peer_cert (const unsigned long binding);
	void evma_accept_ssl_peer (const unsigned long binding);
	#endif

	int evma_get_peername (const unsigned long binding, struct sockaddr*, socklen_t*);
	int evma_get_sockname (const unsigned long binding, struct sockaddr*, socklen_t*);
	int evma_get_subprocess_pid (const unsigned long binding, pid_t*);
	int evma_get_subprocess_status (const unsigned long binding, int*);
	int evma_get_connection_count();
	int evma_send_data_to_connection (const unsigned long binding, const char *data, int data_length);
	int evma_send_datagram (const unsigned long binding, const char *data, int data_length, const char *address, int port);
	float evma_get_comm_inactivity_timeout (const unsigned long binding);
	int evma_set_comm_inactivity_timeout (const unsigned long binding, float value);
	float evma_get_pending_connect_timeout (const unsigned long binding);
	int evma_set_pending_connect_timeout (const unsigned long binding, float value);
	int evma_get_outbound_data_size (const unsigned long binding);
	uint64_t evma_get_last_activity_time (const unsigned long);
	int evma_send_file_data_to_connection (const unsigned long binding, const char *filename);

	void evma_close_connection (const unsigned long binding, int after_writing);
	int evma_report_connection_error_status (const unsigned long binding);
	void evma_signal_loopbreak();
	void evma_set_timer_quantum (int);
	int evma_get_max_timer_count();
	void evma_set_max_timer_count (int);
	void evma_setuid_string (const char *username);
	void evma_stop_machine();
	float evma_get_heartbeat_interval();
	int evma_set_heartbeat_interval(float);

	const unsigned long evma_popen (char * const*cmd_strings);

	const unsigned long evma_watch_filename (const char *fname);
	void evma_unwatch_filename (const unsigned long);

	const unsigned long evma_watch_pid (int);
	void evma_unwatch_pid (const unsigned long);

	void evma_start_proxy(const unsigned long, const unsigned long, const unsigned long, const unsigned long);
	void evma_stop_proxy(const unsigned long);
	unsigned long evma_proxied_bytes(const unsigned long);

	int evma_set_rlimit_nofile (int n_files);

	void evma_set_epoll (int use);
	void evma_set_kqueue (int use);

	uint64_t evma_get_current_loop_time();
#if __cplusplus
}
#endif


#endif // __EventMachine__H_

