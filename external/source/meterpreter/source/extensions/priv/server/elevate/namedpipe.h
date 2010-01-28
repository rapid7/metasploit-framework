#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_TECHNIQUES_NAMEDPIPE_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_TECHNIQUES_NAMEDPIPE_H

DWORD elevate_via_service_namedpipe( Remote * remote, Packet * packet );
DWORD elevate_via_service_namedpipe2( Remote * remote, Packet * packet );

#endif
