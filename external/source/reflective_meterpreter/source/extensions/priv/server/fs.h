#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_FS_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_FS_H

DWORD request_fs_get_file_mace(Remote *remote, Packet *packet);
DWORD request_fs_set_file_mace(Remote *remote, Packet *packet);
DWORD request_fs_set_file_mace_from_file(Remote *remote, Packet *packet);
DWORD request_fs_blank_file_mace(Remote *remote, Packet *packet);
DWORD request_fs_blank_directory_mace(Remote *remote, Packet *packet);

#endif
