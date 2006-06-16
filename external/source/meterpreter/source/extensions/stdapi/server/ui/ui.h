#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_UI_UI_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_UI_UI_H

DWORD extract_hook_library();

DWORD request_ui_enable_keyboard(Remote *remote, Packet *request);
DWORD request_ui_enable_mouse(Remote *remote, Packet *request);
DWORD request_ui_get_idle_time(Remote *remote, Packet *request);

#endif
