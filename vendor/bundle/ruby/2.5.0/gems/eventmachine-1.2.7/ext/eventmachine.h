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

	enum { // SSL/TLS Protocols
		EM_PROTO_SSLv2 = 2,
		EM_PROTO_SSLv3 = 4,
		EM_PROTO_TLSv1 = 8,
		EM_PROTO_TLSv1_1 = 16,
		EM_PROTO_TLSv1_2 = 32
	};

	void evma_initialize_library (EMCallback);
	bool evma_run_machine_once();
	void evma_run_machine();
	void evma_release_library();
	const uintptr_t evma_install_oneshot_timer (uint64_t milliseconds);
	const uintptr_t evma_connect_to_server (const char *bind_addr, int bind_port, const char *server, int port);
	const uintptr_t evma_connect_to_unix_server (const char *server);

	const uintptr_t evma_attach_fd (int file_descriptor, int watch_mode);
	int evma_detach_fd (const uintptr_t binding);
	int evma_get_file_descriptor (const uintptr_t binding);
	int evma_is_notify_readable (const uintptr_t binding);
	void evma_set_notify_readable (const uintptr_t binding, int mode);
	int evma_is_notify_writable (const uintptr_t binding);
	void evma_set_notify_writable (const uintptr_t binding, int mode);

	int evma_pause(const uintptr_t binding);
	int evma_is_paused(const uintptr_t binding);
	int evma_resume(const uintptr_t binding);

	int evma_num_close_scheduled();

	void evma_stop_tcp_server (const uintptr_t binding);
	const uintptr_t evma_create_tcp_server (const char *address, int port);
	const uintptr_t evma_create_unix_domain_server (const char *filename);
	const uintptr_t evma_attach_sd (int sd);
	const uintptr_t evma_open_datagram_socket (const char *server, int port);
	const uintptr_t evma_open_keyboard();
	void evma_set_tls_parms (const uintptr_t binding, const char *privatekey_filename, const char *certchain_filenane, int verify_peer, int fail_if_no_peer_cert, const char *sni_hostname, const char *cipherlist, const char *ecdh_curve, const char *dhparam, int protocols);
	void evma_start_tls (const uintptr_t binding);

	#ifdef WITH_SSL
	X509 *evma_get_peer_cert (const uintptr_t binding);
	int evma_get_cipher_bits (const uintptr_t binding);
	const char *evma_get_cipher_name (const uintptr_t binding);
	const char *evma_get_cipher_protocol (const uintptr_t binding);
	const char *evma_get_sni_hostname (const uintptr_t binding);
	void evma_accept_ssl_peer (const uintptr_t binding);
	#endif

	int evma_get_peername (const uintptr_t binding, struct sockaddr*, socklen_t*);
	int evma_get_sockname (const uintptr_t binding, struct sockaddr*, socklen_t*);
	int evma_get_subprocess_pid (const uintptr_t binding, pid_t*);
	int evma_get_subprocess_status (const uintptr_t binding, int*);
	int evma_get_connection_count();
	int evma_send_data_to_connection (const uintptr_t binding, const char *data, int data_length);
	int evma_send_datagram (const uintptr_t binding, const char *data, int data_length, const char *address, int port);
	float evma_get_comm_inactivity_timeout (const uintptr_t binding);
	int evma_set_comm_inactivity_timeout (const uintptr_t binding, float value);
	float evma_get_pending_connect_timeout (const uintptr_t binding);
	int evma_set_pending_connect_timeout (const uintptr_t binding, float value);
	int evma_get_outbound_data_size (const uintptr_t binding);
	uint64_t evma_get_last_activity_time (const uintptr_t binding);
	int evma_send_file_data_to_connection (const uintptr_t binding, const char *filename);

	void evma_close_connection (const uintptr_t binding, int after_writing);
	int evma_report_connection_error_status (const uintptr_t binding);
	void evma_signal_loopbreak();
	void evma_set_timer_quantum (int);
	int evma_get_max_timer_count();
	void evma_set_max_timer_count (int);
	int evma_get_simultaneous_accept_count();
	void evma_set_simultaneous_accept_count (int);
	void evma_setuid_string (const char *username);
	void evma_stop_machine();
	bool evma_stopping();
	float evma_get_heartbeat_interval();
	int evma_set_heartbeat_interval(float);

	const uintptr_t evma_popen (char * const*cmd_strings);

	const uintptr_t evma_watch_filename (const char *fname);
	void evma_unwatch_filename (const uintptr_t binding);

	const uintptr_t evma_watch_pid (int);
	void evma_unwatch_pid (const uintptr_t binding);

	void evma_start_proxy(const uintptr_t from, const uintptr_t to, const unsigned long bufsize, const unsigned long length);
	void evma_stop_proxy(const uintptr_t from);
	unsigned long evma_proxied_bytes(const uintptr_t from);

	int evma_set_rlimit_nofile (int n_files);

	void evma_set_epoll (int use);
	void evma_set_kqueue (int use);

	uint64_t evma_get_current_loop_time();
#if __cplusplus
}
#endif


#endif // __EventMachine__H_

