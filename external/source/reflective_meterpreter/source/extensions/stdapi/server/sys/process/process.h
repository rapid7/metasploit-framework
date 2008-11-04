#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_PROCESS_PROCESS_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_PROCESS_PROCESS_H

/*
 * The process channel context
 */
typedef struct _ProcessChannelContext
{
	HANDLE pStdin;
	HANDLE pStdout;
} ProcessChannelContext;

DWORD process_channel_read(Channel *channel, Packet *request, 
		LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead);
DWORD process_channel_write(Channel *channel, Packet *request, 
		LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten);
DWORD process_channel_close(Channel *channel, Packet *request, 
		LPVOID context);
DWORD process_channel_interact(Channel *channel, Packet *request, 
		LPVOID context, BOOLEAN interact);

/*
 * Process handlers
 */
DWORD request_sys_process_attach(Remote *remote, Packet *packet);
DWORD request_sys_process_close(Remote *remote, Packet *packet);
DWORD request_sys_process_execute(Remote *remote, Packet *packet);
DWORD request_sys_process_kill(Remote *remote, Packet *packet);
DWORD request_sys_process_get_processes(Remote *remote, Packet *packet);
DWORD request_sys_process_getpid(Remote *remote, Packet *packet);
DWORD request_sys_process_get_info(Remote *remote, Packet *packet);

// Image
DWORD request_sys_process_image_load(Remote *remote, Packet *packet);
DWORD request_sys_process_image_get_proc_address(Remote *remote, Packet *packet);
DWORD request_sys_process_image_unload(Remote *remote, Packet *packet);
DWORD request_sys_process_image_get_images(Remote *remote, Packet *packet);

// Memory
DWORD request_sys_process_memory_allocate(Remote *remote, Packet *packet);
DWORD request_sys_process_memory_free(Remote *remote, Packet *packet);
DWORD request_sys_process_memory_read(Remote *remote, Packet *packet);
DWORD request_sys_process_memory_write(Remote *remote, Packet *packet);
DWORD request_sys_process_memory_query(Remote *remote, Packet *packet);
DWORD request_sys_process_memory_protect(Remote *remote, Packet *packet);
DWORD request_sys_process_memory_lock(Remote *remote, Packet *packet);
DWORD request_sys_process_memory_unlock(Remote *remote, Packet *packet);

// Thread
DWORD request_sys_process_thread_open(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_create(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_close(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_get_threads(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_suspend(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_resume(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_terminate(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_query_regs(Remote *remote, Packet *packet);
DWORD request_sys_process_thread_set_regs(Remote *remote, Packet *packet);

/*
 * Utility methods
 */
DWORD execute_code_stub_in_process(HANDLE process, PVOID buffer, ULONG length,
		LPVOID parameter, DWORD parameterLength, LPDWORD result);


/*
 * Wait methods
 */
DWORD process_wait_notify(Remote * remote, HANDLE handle);
DWORD request_sys_process_wait(Remote *remote, Packet *packet);
#endif
