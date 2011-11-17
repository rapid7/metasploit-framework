#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_POWER_POWER_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_POWER_POWER_H

/*
 * Power interaction packet handlers
 */
DWORD request_sys_power_exitwindows(Remote *remote, Packet *packet);
DWORD request_sys_power_exitlinux(Remote *remote, Packet *packet);

#endif
