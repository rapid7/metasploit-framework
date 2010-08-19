#ifndef _METERPRETER_SERVER_REMOTE_DISPATCHER_H
#define _METERPRETER_SERVER_REMOTE_DISPATCHER_H


/*
 * core_loadlib
 * ------------
 *
 * Load a library into the address space of the executing process.
 *
 * TLVs:
 *
 * req: TLV_TYPE_LIBRARY_PATH -- The path of the library to load.
 * req: TLV_TYPE_FLAGS        -- Library loading flags.
 * opt: TLV_TYPE_TARGET_PATH  -- The contents of the library if uploading.
 * opt: TLV_TYPE_DATA         -- The contents of the library if uploading.
 *
 * TODO:
 *
 *   - Implement in-memory library loading
 */
DWORD request_core_loadlib(Remote *remote, Packet *packet);


VOID register_dispatch_routines();
VOID deregister_dispatch_routines( Remote * remote );

#endif
