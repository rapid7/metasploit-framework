#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_EVENTLOG_EVENTLOG_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_EVENTLOG_EVENTLOG_H

/*
 * Event log interaction packet handlers
 */
DWORD request_sys_eventlog_open(Remote *remote, Packet *packet);
DWORD request_sys_eventlog_numrecords(Remote *remote, Packet *packet);
DWORD request_sys_eventlog_read(Remote *remote, Packet *packet);
DWORD request_sys_eventlog_oldest(Remote *remote, Packet *packet);
DWORD request_sys_eventlog_clear(Remote *remote, Packet *packet);
DWORD request_sys_eventlog_close(Remote *remote, Packet *packet);

#endif
